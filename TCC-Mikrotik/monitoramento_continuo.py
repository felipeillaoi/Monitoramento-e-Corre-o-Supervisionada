from __future__ import annotations
import copy
import json
import math
import os
import time
import uuid
from pathlib import Path
from investigacao_interfaces import PORTS, basic_valid
from contexto_supervisionado import stamp

DEFAULT_PROFILE = Path(__file__).with_name("perfil_supervisionado.json")
RETRYABLE = {
    "pendente_revisao_gpt",
    "sem_acao_executavel_revisao_pendente",
    "simulacao_sem_revisao",
    "erro_analise",
    "evidencias_expiradas_antes_reformulacao",
    "proposta_expirada_antes_aprovacao",
    "proposta_expirada_apos_aprovacao",
    "intervalo_SET_300s",
}


def load_profile(path=DEFAULT_PROFILE):
    profile = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    ports = profile.get("interfaces")
    if not isinstance(ports, dict) or set(ports) != set(PORTS):
        raise ValueError(
            "Perfil deve declarar ether1, ether2 e ether5; outras portas ainda nao pertencem ao catalogo."
        )
    for name, spec in ports.items():
        if not isinstance(spec, dict) or set(spec) != {
            "admin_desejado",
            "link_exigido",
            "propor_habilitacao",
        }:
            raise ValueError("Campos invalidos no perfil de " + name)
        if type(spec["admin_desejado"]) is not int or spec["admin_desejado"] not in (1, 2):
            raise ValueError("admin_desejado deve ser 1 ou 2.")
        if type(spec["link_exigido"]) is not bool or type(spec["propor_habilitacao"]) is not bool:
            raise ValueError("Expectativas do perfil devem usar true/false.")
        if spec["propor_habilitacao"] and (
            not PORTS[name]["habilitacao_permitida"] or spec["admin_desejado"] != 1
        ):
            raise ValueError(
                "Perfil nao pode liberar porta protegida nem habilitacao contraria ao estado desejado."
            )
        if spec["admin_desejado"] == 2 and spec["link_exigido"]:
            raise ValueError("Porta desejada desabilitada nao pode exigir link.")
        if spec["link_exigido"] != PORTS[name]["link_esperado"]:
            raise ValueError("Exigencia de link deve respeitar o perfil homologado desta RB750Gr3.")
    for key, lower, upper in (("reavaliacao_s", 300, 86400), ("repetir_alerta_s", 60, 86400)):
        if type(profile.get(key)) is not int or not lower <= profile[key] <= upper:
            raise ValueError("Intervalo invalido no perfil: " + key)
    return profile


def current_signals(metrics, states, context, profile, reference):
    signals = {}
    ref = stamp(reference)
    for key, field, threshold in (
        ("cpu", "cpu_media_pct", context["limiar_cpu_pct"]),
        ("ram", "memoria_pct", context["limiar_ram_pct"]),
    ):
        value = metrics.get(field) if metrics.get("tem_dados") else None
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 100:
            signals[key] = "dados_indisponiveis"
        elif value >= threshold:
            signals[key] = "acima_do_limiar"
    for name, spec in profile["interfaces"].items():
        state = states.get(name, {})
        when = stamp(state.get("utc"))
        age = (ref - when).total_seconds() if ref and when else None
        if (
            not basic_valid(state)
            or state.get("nome") != name
            or age is None
            or not 0 <= age <= 120
        ):
            signals["interface:" + name] = "dados_indisponiveis"
        elif state["admin_status"] != spec["admin_desejado"] or (
            spec["link_exigido"] and state["oper_status"] != 1
        ):
            oper = state["oper_status"] if spec["link_exigido"] else "opcional"
            signals["interface:" + name] = f"admin={state['admin_status']};oper={oper}"
    return signals


class IncidentTracker:
    def __init__(self, path, profile, reset=False, clock=time.time):
        self.path, self.profile, self.clock = Path(path), copy.deepcopy(profile), clock
        self.entries = {}
        self.events = []
        if self.path.exists() and not reset:
            saved = json.loads(self.path.read_text(encoding="utf-8"))
            if saved.get("versao") != 1 or not isinstance(saved.get("incidentes"), dict):
                raise ValueError(
                    "Controle de incidentes invalido; preserve o arquivo e use --reavaliar-pendencias."
                )
            if saved.get("perfil") == profile:
                self.entries = saved["incidentes"]
        self.persist()

    def persist(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as stream:
            json.dump(
                {"versao": 1, "perfil": self.profile, "incidentes": self.entries},
                stream,
                ensure_ascii=False,
                indent=2,
                allow_nan=False,
            )
            stream.flush()
            os.fsync(stream.fileno())
        tmp.replace(self.path)

    def observe(self, signals):
        self.events = []
        signals = dict(signals)
        for key, state in list(signals.items()):
            if (
                state == "dados_indisponiveis"
                and key in self.entries
                and self.entries[key]["estado"] != state
            ):
                signals["coleta:" + key] = state
                del signals[key]
        current = self.clock()

        for key in list(self.entries):
            if key not in signals and "coleta:" + key not in signals:
                self.events.append(
                    {"evento": "resolvido_por_leitura", "chave": key, "id": self.entries[key]["id"]}
                )
                del self.entries[key]
        for key, state in signals.items():
            old = self.entries.get(key)
            name = key.removeprefix("interface:") if key.startswith("interface:") else None

            recurrent = (
                old is not None
                and name in self.profile["interfaces"]
                and self.profile["interfaces"][name]["admin_desejado"] == 1
                and old.get("resultado")
                in ("habilitacao_confirmada", "habilitada_sem_confirmacao_SET")
                and state.startswith("admin=2;")
            )
            if old is None or old["estado"] != state or recurrent:
                self.entries[key] = {
                    "id": uuid.uuid4().hex[:12],
                    "estado": state,
                    "inicio_epoch": current,
                    "analise_epoch": None,
                    "resultado": None,
                    "alerta_epoch": None,
                }
                self.events.append(
                    {
                        "evento": "novo_episodio",
                        "chave": key,
                        "id": self.entries[key]["id"],
                        "estado": state,
                    }
                )
                if recurrent:
                    self.events[-1].update(
                        motivo="desabilitada_apos_habilitacao_confirmada",
                        episodio_anterior=old["id"],
                    )
        self.persist()
        return [key for key in signals if self.due(key)]

    def reconcile_post_set(self, snapshot, context, reference):
        name = snapshot.get("nome") if isinstance(snapshot, dict) else None
        if name not in self.profile["interfaces"]:
            return None
        signal = current_signals(
            {"tem_dados": False}, {name: snapshot}, context, self.profile, reference
        ).get("interface:" + name)
        if signal == "dados_indisponiveis" or snapshot.get("admin_status") != 1:
            return None
        key = "interface:" + name
        old = self.entries.get(key)
        if signal is None:
            self.entries.pop(key, None)
            event = {
                "evento": "resolvido_por_GET_pos_SET",
                "chave": key,
                "id": old["id"] if old else None,
            }
        elif old is None or old["estado"] != signal:
            self.entries[key] = {
                "id": uuid.uuid4().hex[:12],
                "estado": signal,
                "inicio_epoch": self.clock(),
                "analise_epoch": None,
                "resultado": None,
                "alerta_epoch": None,
            }
            event = {
                "evento": "novo_episodio_por_GET_pos_SET",
                "chave": key,
                "id": self.entries[key]["id"],
                "estado": signal,
            }
        else:
            return None
        self.persist()
        return event

    def due(self, key):
        item = self.entries[key]
        if item["analise_epoch"] is None:
            return True
        when = self.next_analysis(key)
        return when is not None and self.clock() >= when

    def next_analysis(self, key):
        item = self.entries[key]
        if item["analise_epoch"] is None:
            return self.clock()
        if item["resultado"] not in RETRYABLE:
            return None
        if item["resultado"] == "intervalo_SET_300s":
            when = item.get("reavaliar_epoch", item["analise_epoch"] + 300)
            if type(when) in (int, float) and math.isfinite(when):
                return when
        return item["analise_epoch"] + self.profile["reavaliacao_s"]

    def waiting(self):
        result = []
        for key, item in self.entries.items():
            when = self.next_analysis(key)
            result.append(
                {
                    "chave": key,
                    "resultado_anterior": item["resultado"],
                    "proxima_analise_epoch": when,
                    "restante_s": max(0, math.ceil(when - self.clock()))
                    if when is not None
                    else None,
                }
            )
        return result

    def complete(self, keys, result, retry_at=None):
        for key in keys:
            if key in self.entries:
                self.entries[key].update(analise_epoch=self.clock(), resultado=result)
                self.entries[key].pop("reavaliar_epoch", None)
                if (
                    result == "intervalo_SET_300s"
                    and type(retry_at) in (int, float)
                    and math.isfinite(retry_at)
                ):
                    self.entries[key]["reavaliar_epoch"] = retry_at
        self.persist()

    def remind(self):
        current = self.clock()
        reminders = []
        for key, item in self.entries.items():
            if (
                item["alerta_epoch"] is None
                or current - item["alerta_epoch"] >= self.profile["repetir_alerta_s"]
            ):
                reminders.append({"chave": key, **item})
                item["alerta_epoch"] = current
        self.persist()
        return reminders


def write_hold_status(folder, session, epoch=None):
    if session.get("tentativas", 0) >= session.get("limite", 1):
        return "limite_SET_sessao", None
    path = Path(folder) / "controle" / "ultima_tentativa_ether5.json"
    if not path.exists():
        return None, None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))["epoch"]
        if type(value) not in (int, float) or not math.isfinite(value):
            return "controle_SET_invalido", None
        age = (time.time() if epoch is None else epoch) - value
        return ("intervalo_SET_300s", value + 300) if age < 300 else (None, None)
    except (ValueError, KeyError, OSError, TypeError):
        return "controle_SET_invalido", None


def write_hold(folder, session, epoch=None):
    return write_hold_status(folder, session, epoch)[0]


class MonitorLock:
    def __init__(self, path):
        self.path = Path(path)
        self.owned = False

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise ValueError(
                "Monitor ja ativo ou trava de sessao anterior presente: "
                + str(self.path)
                + ". Encerre a outra instancia; se ela ja terminou, remova somente essa trava .lock."
            ) from exc
        self.owned = True
        os.close(fd)
        return self

    def __exit__(self, *_):
        if self.owned:
            self.path.unlink(missing_ok=True)
            self.owned = False
