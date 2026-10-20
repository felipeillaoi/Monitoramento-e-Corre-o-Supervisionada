from contexto_supervisionado import stamp


def compile_facts(packet):
    result = {
        "origem": "resumo_das_mesmas_evidencias; nao e medicao independente",
        "interfaces": [],
        "wan": {"tem_dados": False},
    }
    for row in packet.get("interfaces", []):
        age = row.get("idade_s")
        if type(age) not in (int, float) or not 0 <= age <= 120:
            continue
        if type(row.get("admin_status")) is not int or type(row.get("oper_status")) is not int:
            continue
        result["interfaces"].append(
            {k: row[k] for k in ("interface", "admin_status", "oper_status", "evidencia")}
        )
    for ev in reversed(packet.get("evidencias", [])):
        if ev.get("ferramenta") != "consultar_estado_wan":
            continue
        d = ev.get("dados", {})
        age = ev.get("idade_consulta_s")
        reference = stamp(packet.get("referencia_utc"))
        when = stamp(d.get("utc"))
        fresh = bool(reference and when and 0 <= (reference - when).total_seconds() <= 120)
        if d.get("tem_dados") and type(age) in (int, float) and 0 <= age <= 120 and fresh:
            result["wan"] = {
                "tem_dados": True,
                "evidencia": ev["id"],
                "dhcp": {
                    k: d.get("dhcp", {}).get(k)
                    for k in ("disabled", "invalid", "status", "address")
                }
                if isinstance(d.get("dhcp"), dict)
                else {},
                "ipv4_ativos_ether1": d.get("ipv4_count"),
                "rotas_PADRAO_ipv4_MAIN_ativas": d.get("default_routes"),
                "dns_servers_e_dynamic_servers": d.get("dns_servers"),
                "doh_configurado": d.get("doh_configured"),
            }
        break
    result["limites"] = [
        "DHCP.disabled nao e ifAdminStatus. oper_status=1 e link up, mesmo sem IP.",
        "Rotas padrao IPv4/main=0 nao significa tabela vazia ou ausencia de qualquer caminho.",
        "DNS upstream vazio nao testa resolucao no PC; null significa desconhecido.",
        "ether5 sem exigencia de link no laboratorio: oper_status=2 nao prova defeito nem cabo ausente.",
        "Ausencias de IP/rota/DNS podem estar relacionadas ao DHCP, mas nao sao quatro causas independentes.",
    ]
    return result
