import asyncio
from datetime import timedelta
from getpass import getpass

from pysnmp.hlapi.v3arch.asyncio import (
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
    usmAesCfb128Protocol,
    usmHMACSHAAuthProtocol,
)
from pysnmp.proto.rfc1905 import EndOfMibView, NoSuchInstance, NoSuchObject

ROTEADOR = "192.168.88.1"
USUARIO = "tcc-monitor"
CONSULTAS = (
    ("Nome", "1.3.6.1.2.1.1.5.0"),
    ("Descricao do sistema", "1.3.6.1.2.1.1.1.0"),
    ("Tempo de atividade do servico SNMP", "1.3.6.1.2.1.1.3.0"),
)


async def consultar(senha_auth: str, senha_priv: str) -> int:
    engine = SnmpEngine()
    try:
        alvo = await UdpTransportTarget.create((ROTEADOR, 161), timeout=3, retries=1)
        usuario = UsmUserData(
            USUARIO,
            authKey=senha_auth,
            privKey=senha_priv,
            authProtocol=usmHMACSHAAuthProtocol,
            privProtocol=usmAesCfb128Protocol,
        )
        print(f"\nConsultando {ROTEADOR}:161 por SNMPv3...", flush=True)
        erro, status, indice, respostas = await asyncio.wait_for(
            get_cmd(
                engine,
                usuario,
                alvo,
                ContextData(),
                *(ObjectType(ObjectIdentity(oid)) for _, oid in CONSULTAS),
                lookupMib=False,
            ),
            timeout=20,
        )
        if erro:
            print(f"Falha SNMP: {erro}")
            print("Confira usuario, senhas, SHA1/AES e origem permitida 192.168.88.50/32.")
            print("Em caso de timeout, confira tambem o acesso UDP/161 ao roteador.")
            return 1
        if status:
            print(f"Erro retornado pela RB: {status.prettyPrint()} (item {indice})")
            return 1

        leituras = dict((str(oid), valor) for oid, valor in respostas)
        completas = True
        for nome, oid in CONSULTAS:
            valor = leituras.get(oid)
            if valor is None or isinstance(valor, (NoSuchObject, NoSuchInstance, EndOfMibView)):
                print(f"{nome}: OID indisponivel ({oid})")
                completas = False
                continue
            exibicao = valor.prettyPrint()
            if oid == "1.3.6.1.2.1.1.3.0":
                exibicao = str(timedelta(seconds=int(valor) / 100))
            print(f"{nome}: {exibicao}")

        print(
            "\nLeitura SNMPv3 concluida."
            if completas
            else "\nResposta recebida, mas a leitura ficou incompleta."
        )
        return 0 if completas else 1
    except TimeoutError:
        print("Tempo limite de 20 segundos excedido. Confira conectividade e configuracao SNMP.")
        return 1
    except Exception as exc:
        print(f"Falha na consulta ({type(exc).__name__}): {exc}")
        return 1
    finally:
        engine.close_dispatcher()


def main() -> int:
    print("Teste de leitura SNMPv3 - laboratorio TCC")
    print(f"Roteador: {ROTEADOR} | Usuario: {USUARIO} | SHA1 + AES")
    senha_auth = getpass("Senha de autenticacao: ")
    senha_priv = getpass("Senha de criptografia: ")
    if len(senha_auth) < 8 or len(senha_priv) < 8:
        print("As duas senhas devem ter pelo menos 8 caracteres.")
        return 1
    return asyncio.run(consultar(senha_auth, senha_priv))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nTeste interrompido.")
        raise SystemExit(130)
