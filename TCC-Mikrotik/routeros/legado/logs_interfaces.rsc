/system script add name=tcc-logs-interfaces policy=read source={
    :local entries [/log find where message~"ether1|ether5"];
    :local total [:len $entries];
    :local first ($total - 5);
    :if ($first < 0) do={ :set first 0; };
    :local result "TCCLOGSv1";
    :foreach entry in=[:pick $entries $first $total] do={
        :local stamp [/log get $entry time];
        :local text [/log get $entry message];
        :set result ($result . "\n" . $stamp . " | " . [:pick $text 0 160]);
    };
    :if ($total = 0) do={ :set result ($result . "\nSEM_ENTRADAS_NO_FILTRO"); };
    :put $result;
}
