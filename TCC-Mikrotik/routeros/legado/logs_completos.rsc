/system script add name=tcc-logs-iniciar-v2 policy=read source={
    :global tccLogV2Rows;
    :global tccLogV2Count;
    :global tccLogV2Token;
    :global tccLogV2Pos;
    :global tccLogV2Seq;
    :global tccLogV2Hex;
    :global tccLogV2Offset;
    :set tccLogV2Token "";
    :set tccLogV2Rows [/log print as-value];
    :set tccLogV2Count [:len $tccLogV2Rows];
    :if ($tccLogV2Count > 5000) do={
        :set tccLogV2Rows [:toarray ""];
        :error "TCC: buffer maior que 5000 registros; coleta nao iniciada";
    };
    :set tccLogV2Token [:tostr [:timestamp]];
    :set tccLogV2Pos 0;
    :set tccLogV2Seq 0;
    :set tccLogV2Hex "";
    :set tccLogV2Offset 0;
    :put ("TCCLOGSv2|BEGIN|" . $tccLogV2Token . "|" . $tccLogV2Count);
}

/system script add name=tcc-logs-proxima-v2 policy=read source={
    :global tccLogV2Rows;
    :global tccLogV2Count;
    :global tccLogV2Token;
    :global tccLogV2Pos;
    :global tccLogV2Seq;
    :global tccLogV2Hex;
    :global tccLogV2Offset;
    :if (([:typeof $tccLogV2Token] != "str") || ([:len $tccLogV2Token] = 0)) do={
        :error "TCC: execute primeiro tcc-logs-iniciar-v2";
    };
    :if ($tccLogV2Pos >= $tccLogV2Count) do={
        :put ("TCCLOGSv2|END|" . $tccLogV2Token . "|" . $tccLogV2Seq . "|" . $tccLogV2Count);
        :set tccLogV2Rows [:toarray ""];
    } else={
        :if ([:len $tccLogV2Hex] = 0) do={
            :local tccEntry ($tccLogV2Rows->$tccLogV2Pos);
            :local tccRow {"id"=[:tostr ($tccEntry->".id")]; "time"=[:tostr ($tccEntry->"time")]; "topics"=[:tostr ($tccEntry->"topics")]; "message"=[:tostr ($tccEntry->"message")]};
            :local tccRaw [:serialize value=$tccRow to=json options=json.no-string-conversion];
            :if ([:len $tccRaw] > 65536) do={ :error "TCC: mensagem acima do limite de transferencia"; };
            :set tccLogV2Hex [:convert $tccRaw from=raw to=hex];
            :set tccLogV2Offset 0;
        };
        :local tccSize ([:len $tccLogV2Hex] / 2);
        :local tccChunk [:pick $tccLogV2Hex ($tccLogV2Offset * 2) (($tccLogV2Offset + 450) * 2)];
        :put ("TCCLOGSv2|DATA|" . $tccLogV2Token . "|" . $tccLogV2Seq . "|" . $tccLogV2Pos . "|" . $tccLogV2Offset . "|" . $tccSize . "|" . $tccChunk);
        :set tccLogV2Seq ($tccLogV2Seq + 1);
        :set tccLogV2Offset ($tccLogV2Offset + ([:len $tccChunk] / 2));
        :if ($tccLogV2Offset >= $tccSize) do={
            :set tccLogV2Pos ($tccLogV2Pos + 1);
            :set tccLogV2Hex "";
            :set tccLogV2Offset 0;
        };
    };
}
