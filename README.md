# DiskTool

Ferramenta para Windows de **verificação de saúde, testes, apagamento seguro e formatação de discos** NVMe, SSD e HDD, com laudo técnico e certificado de apagamento em PDF.

## Download

Baixe o **`DiskTool.exe`** na página de [Releases](../../releases/latest). É um arquivo único: coloque numa pasta (ex.: `C:\DiskTool`) e execute. O programa pede permissão de administrador, que é necessária para ler os discos.

> O executável não tem assinatura digital, então o Windows SmartScreen pode avisar na primeira vez. Clique em **Mais informações → Executar assim mesmo**.

### smartctl (recomendado)

Para dados SMART completos e o autoteste dos discos, instale o **smartmontools** pelo site oficial: <https://www.smartmontools.org/> ([download para Windows](https://github.com/smartmontools/smartmontools/releases)). O DiskTool encontra o `smartctl.exe` automaticamente se ele estiver:

- instalado em `C:\Program Files\smartmontools\bin` (o padrão do instalador), ou
- na pasta do DiskTool, em `smartmontools\bin\`, ou
- no `PATH`.

Sem o smartctl o programa funciona, mas com menos dados. Discos NVMe continuam com saúde, desgaste e TB gravados completos, porque são lidos direto pelo Windows.

## Funções

- **Saúde dos discos**, no estilo CrystalDiskInfo: saúde %, temperatura, horas ligado, setores realocados/pendentes, erros de mídia, atributos SMART traduzidos.
- **Durabilidade / TBW**: total gravado × TBW garantido pelo fabricante, desgaste real e estimativa de vida restante.
- **✔ Diagnóstico completo** (um clique): análise SMART, autoteste curto do disco, teste rápido de leitura e laudo técnico em PDF.
- **Modo bancada**: diagnostica automaticamente cada disco que for conectado (USB, dock, SATA hot-swap).
- **Registro de laudos** (planilha CSV) e aviso quando um disco que já passou pela bancada volta.
- **Histórico e gráficos** de saúde, TB gravados e temperatura; monitoramento diário opcional (tarefa agendada) com aviso se algum disco piorar.
- **Testes**: leitura completa, leitura por amostragem, autoteste SMART curto/longo, benchmark (sequencial e 4K) e teste de capacidade real (pendrive/cartão falsificado).
- **Apagamento**: formatação rápida com TRIM, zeragem completa com verificação, apagamento seguro pelo controlador (NVMe/SSD). Gera **certificado de apagamento** (PDF + registro CSV com hash SHA-256).
- **Reparo de setores** ilegíveis em HDD.
- Proteção do disco do sistema, alerta de BitLocker, pausa automática por temperatura, tema claro/escuro.

Laudos e certificados podem ter o nome, contato e logo da sua empresa (**Configurações**).

## ⚠️ Atenção

As funções de **apagamento destroem todos os dados do disco selecionado** de forma irreversível. O programa pede a digitação de uma confirmação e bloqueia o disco do sistema, mas confira sempre o modelo e o número de série antes de confirmar. Use por sua conta e risco.

## Requisitos

- Windows 10 ou 11 (64 bits), Windows PowerShell 5.1 (já vem com o Windows)
- Microsoft Edge (já vem com o Windows), usado para gerar os PDFs

## Executar a partir do código-fonte

```
Iniciar DiskTool.bat
```

ou `powershell -ExecutionPolicy Bypass -File DiskTool.ps1`. Modo texto, somente leitura: `DiskTool.ps1 -ListOnly`.

## Compilar o .exe

```
powershell -ExecutionPolicy Bypass -File build\Build-Exe.ps1
```

Usa o compilador C# do .NET Framework que já vem no Windows. O `DiskTool.exe` gerado embute o `DiskTool.ps1`. Salve o `.ps1` sempre em **UTF-8 com BOM**, senão os acentos quebram no PowerShell 5.1.

## Pastas criadas ao lado do programa

| Pasta / arquivo | Conteúdo |
|---|---|
| `Historico\` | leituras de saúde de cada disco (por número de série) |
| `Laudos\` | laudos técnicos (PDF) e `Registro_de_laudos.csv` |
| `Certificados\` | certificados de apagamento e `Registro_de_apagamentos.csv` |
| `DiskTool.log` | registro de todas as operações |
| `DiskTool.config.json` | configurações (empresa, técnico, logo, tema) |
