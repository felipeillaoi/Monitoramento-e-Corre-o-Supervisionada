/system script add name=tcc-logs-iniciar-v3 policy=ftp,read,write dont-require-permissions=no source={
    :local tccStage "entrada";
    :onerror tccError {
        :set tccStage "verificar_tmpfs";
        :if ([:len [/disk find where slot="tcc-logram" and type="tmpfs"]] != 1) do={ :error "TCC: tmpfs tcc-logram ausente"; };
        :set tccStage "validar_montagem_RAM";
        :if ([:len [/file find where name="tcc-logram" and type="disk"]] != 1) do={ :error "TCC: pasta RAM tcc-logram nao montada"; };
        :local tccDataFile "tcc-logram/snapshot.txt";
        :local tccStateFile "tcc-logram/cursor.txt";
        :set tccStage "criar_cursor";
        :if ([:len [/file find where name=$tccStateFile]] = 0) do={ /file add name=$tccStateFile type=file; };
        :set tccStage "limpar_cursor";
        /file set [find where name=$tccStateFile] contents="";
        :set tccStage "ler_log_as_value";
        :local tccRows [/log print as-value];
        :set tccStage "contar_registros";
        :local tccCount [:len $tccRows];
        :set tccStage "validar_quantidade";
        :if ($tccCount > 5000) do={ :error "TCC: mais de 5000 registros; coleta nao iniciada"; };
        :set tccStage "remover_snapshot_anterior";
        :if ([:len [/file find where name=$tccDataFile]] > 0) do={ /file remove [find where name=$tccDataFile]; };
        :set tccStage "exportar_JSON_para_RAM";
        :serialize value=$tccRows to=json options=json.no-string-conversion file-name=$tccDataFile;
        :set tccStage "localizar_snapshot";
        :if ([:len [/file find where name=$tccDataFile]] != 1) do={ :error "TCC: exportacao JSON nao encontrada no caminho esperado"; };
        :set tccStage "ler_tamanho_snapshot";
        :local tccBytes [/file get [find where name=$tccDataFile] size];
        :set tccStage "validar_tamanho";
        :if (($tccBytes < 2) || ($tccBytes > 8388608)) do={ :error "TCC: snapshot fora do limite de 8 MiB"; };
        :set tccStage "gerar_token";
        :local tccToken [:tostr [:timestamp]];
        :set tccStage "montar_cursor";
        :local tccState {"token"=$tccToken; "count"=$tccCount; "bytes"=$tccBytes; "offset"=0; "seq"=0};
        :set tccStage "gravar_cursor";
        /file set [find where name=$tccStateFile] contents=[:serialize value=$tccState to=json options=json.no-string-conversion];
        :set tccStage "emitir_manifesto";
        :put ("TCCLOGSv3|BEGIN|" . $tccToken . "|" . $tccCount . "|" . $tccBytes);
    } do={
        :error ("TCC v3 etapa=" . $tccStage . " | " . $tccError);
    };
}

/system script add name=tcc-logs-proxima-v3 policy=ftp,read,write,test dont-require-permissions=no source={
    :local tccStage "entrada";
    :onerror tccError {
        :set tccStage "verificar_tmpfs";
        :if ([:len [/disk find where slot="tcc-logram" and type="tmpfs"]] != 1) do={ :error "TCC: tmpfs tcc-logram ausente"; };
        :set tccStage "validar_montagem_RAM";
        :if ([:len [/file find where name="tcc-logram" and type="disk"]] != 1) do={ :error "TCC: pasta RAM tcc-logram nao montada"; };
        :local tccDataFile "tcc-logram/snapshot.txt";
        :local tccStateFile "tcc-logram/cursor.txt";
        :set tccStage "localizar_cursor";
        :if ([:len [/file find where name=$tccStateFile]] != 1) do={ :error "TCC: inicie a coleta v3 primeiro"; };
        :set tccStage "ler_cursor_JSON";
        :local tccState [:deserialize [/file get [find where name=$tccStateFile] contents] from=json options=json.no-string-conversion];
        :local tccToken ($tccState->"token");
        :local tccCount ($tccState->"count");
        :local tccBytes ($tccState->"bytes");
        :local tccOffset ($tccState->"offset");
        :local tccSeq ($tccState->"seq");
        :set tccStage "validar_tamanho";
        :if (($tccBytes < 2) || ($tccBytes > 8388608) || ($tccOffset < 0) || ($tccOffset > $tccBytes)) do={ :error "TCC: cursor invalido"; };
        :set tccStage "localizar_snapshot";
        :if ([:len [/file find where name=$tccDataFile]] != 1) do={ :error "TCC: snapshot RAM ausente"; };
        :set tccStage "validar_tamanho_snapshot";
        :if ([/file get [find where name=$tccDataFile] size] != $tccBytes) do={ :error "TCC: tamanho do snapshot mudou"; };
        :if ($tccOffset = $tccBytes) do={
            :put ("TCCLOGSv3|END|" . $tccToken . "|" . $tccSeq . "|" . $tccCount . "|" . $tccBytes);
        } else={
            :set tccStage "ler_bloco_RAM";
            :local tccRead [/file read file=$tccDataFile offset=$tccOffset chunk-size=450 as-value];
            :set tccStage "extrair_dados_bloco";
            :local tccChunk ($tccRead->"data");
            :local tccSize [:len $tccChunk];
            :if (($tccSize < 1) || ($tccSize > 450)) do={ :error "TCC: leitura de bloco RAM invalida"; };
            :set ($tccState->"offset") ($tccOffset + $tccSize);
            :set ($tccState->"seq") ($tccSeq + 1);
            :set tccStage "avancar_cursor";
            /file set [find where name=$tccStateFile] contents=[:serialize value=$tccState to=json options=json.no-string-conversion];
            :set tccStage "emitir_bloco";
            :put ("TCCLOGSv3|DATA|" . $tccToken . "|" . $tccSeq . "|" . $tccOffset . "|" . $tccBytes . "|" . [:convert $tccChunk from=raw to=hex]);
        };
    } do={
        :error ("TCC v3 etapa=" . $tccStage . " | " . $tccError);
    };
}
