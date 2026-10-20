:local tccObserver [/system script find where name="tcc-observar-wan-v1"];
:if ([:len $tccObserver] != 1) do={ :error "TCC: necessario exatamente um script tcc-observar-wan-v1; nada atualizado"; };
/system script set $tccObserver policy=read dont-require-permissions=no source={
    :local tccPort [/interface ethernet find where name="ether1"];
    :if ([:len $tccPort] != 1) do={ :error "TCC: ether1 ausente ou ambigua"; };
    :local tccMac [:tostr [/interface ethernet get $tccPort mac-address]];
    :local tccData {"version"=1;"interface"="ether1";"mac"=$tccMac;"dhcp_count"=-1;"dhcp"="";"ipv4_count"=-1;"default_routes"=-1;"dns_servers"=-1;"doh_configured"=false;"free_hdd"=-1;"total_hdd"=-1;"errors"=""};
    :onerror tccError {
        :local tccRows [/ip dhcp-client print as-value where interface="ether1"];
        :set ($tccData->"dhcp_count") [:len $tccRows];
        :if ([:len $tccRows] = 1) do={
            :local tccRow [:pick $tccRows 0];
            :local tccId ($tccRow->".id");
            :local tccClient {"id"=[:tostr $tccId];"disabled"=[/ip dhcp-client get $tccId disabled];"invalid"=[/ip dhcp-client get $tccId invalid];"status"=[:tostr ($tccRow->"status")];"address"=[:tostr ($tccRow->"address")];"gateway"=[:tostr ($tccRow->"gateway")];"add_default_route"=[:tostr [/ip dhcp-client get $tccId add-default-route]]};
            :set ($tccData->"dhcp") $tccClient;
        };
    } do={ :set ($tccData->"dhcp_count") -1; :set ($tccData->"dhcp") ""; :set ($tccData->"errors") (($tccData->"errors") . ";dhcp"); };
    :onerror tccError {
        :set ($tccData->"ipv4_count") [:len [/ip address find where interface="ether1" and disabled=no and invalid=no]];
    } do={ :set ($tccData->"errors") (($tccData->"errors") . ";ipv4"); };
    :onerror tccError {
        :set ($tccData->"default_routes") [:len [/ip route find where dst-address="0.0.0.0/0" and routing-table="main" and active=yes]];
    } do={ :set ($tccData->"errors") (($tccData->"errors") . ";route"); };
    :onerror tccError {
        :set ($tccData->"dns_servers") ([:len [/ip dns get servers]] + [:len [/ip dns get dynamic-servers]]);
        :set ($tccData->"doh_configured") ([:len [:tostr [/ip dns get use-doh-server]]] > 0);
    } do={ :set ($tccData->"dns_servers") -1; :set ($tccData->"errors") (($tccData->"errors") . ";dns"); };
    :onerror tccError {
        :set ($tccData->"free_hdd") [/system resource get free-hdd-space];
        :set ($tccData->"total_hdd") [/system resource get total-hdd-space];
    } do={ :set ($tccData->"errors") (($tccData->"errors") . ";disk"); };
    :put ("TCCWANv1|" . [:serialize value=$tccData to=json options=json.no-string-conversion]);
};
:put "TCC: observacao WAN atualizada para v0.5.2. Nenhuma configuracao de rede foi alterada.";
