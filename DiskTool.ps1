<#
    DiskTool 2.8 - Verificação de saúde e formatação/zeragem de discos (NVMe, SSD e HDD)

    Uso:
      - DiskTool.exe ou "Iniciar DiskTool.bat" (pedem permissão de administrador).
      - Modo texto (somente leitura, sem GUI):  powershell -ExecutionPolicy Bypass -File DiskTool.ps1 -ListOnly

    Pastas criadas ao lado do programa:
      Historico\     - leituras de saúde de cada disco (por número de série)
      Certificados\  - certificados de apagamento (PDF/HTML/TXT)
      DiskTool.log   - registro de todas as operações
#>
param([switch]$ListOnly, [switch]$Monitor, [string]$AppDir, [string]$AppExe)

$ErrorActionPreference = 'Stop'
$AppVersion = '2.8'
$ScriptDir  = Split-Path -Parent $PSCommandPath
if ($AppDir) { $ScriptDir = $AppDir }   # quando iniciado pelo DiskTool.exe: pasta do .exe
$LogFile  = Join-Path $ScriptDir 'DiskTool.log'
$HistDir  = Join-Path $ScriptDir 'Historico'
$CertDir  = Join-Path $ScriptDir 'Certificados'
$SettingsFile = Join-Path $ScriptDir 'DiskTool.config.json'

function Test-Admin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------------- Elevação
if (-not $ListOnly -and -not $Monitor -and -not (Test-Admin)) {
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$PSCommandPath`""
    } catch { }
    exit
}

# ---------------------------------------------------------------- Acesso direto ao disco
if (-not ('DiskJob' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

// Uma operação de baixo nível num disco físico, executada em thread própria.
// Modos: zero, read, sample, verify, verifysample, erase
public class DiskJob
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sa,
                                            uint disposition, uint flags, IntPtr template);

    [StructLayout(LayoutKind.Sequential)]
    struct STORAGE_REINITIALIZE_MEDIA { public uint Version, Size, TimeoutInSeconds, SanitizeOption; }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(SafeFileHandle h, uint code, ref STORAGE_REINITIALIZE_MEDIA inBuf, int inSize,
                                       IntPtr outBuf, int outSize, out int returned, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "DeviceIoControl")]
    static extern bool DeviceIoControlSimple(SafeFileHandle h, uint code, IntPtr inBuf, int inSize,
                                             IntPtr outBuf, int outSize, out int returned, IntPtr overlapped);

    const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
    const uint FILE_SHARE_RW = 3, OPEN_EXISTING = 3, FILE_FLAG_WRITE_THROUGH = 0x80000000;
    const uint IOCTL_STORAGE_REINITIALIZE_MEDIA = 0x002D9640;
    const uint FSCTL_LOCK_VOLUME = 0x00090018, FSCTL_DISMOUNT_VOLUME = 0x00090020;
    const int SEGMENTS = 200;

    public int Disk;
    public string Mode;
    public long DiskSize;
    public int Samples = 2000;

    // Reparo de setores (modo "repair")
    public List<long> RepairBlocks = new List<long>();   // início de cada bloco de 1 MB ilegível
    public string[] VolumeLetters;                        // unidades do disco a travar durante o reparo
    public int SectorSize = 4096;                         // setor físico
    public int BadSectors, FixedSectors, StillBad;
    public List<long> BadSectorOffsets = new List<long>();

    // Benchmark (modo "bench") - usa um arquivo temporário na unidade, não mexe nos dados existentes
    public string BenchPath;          // ex.: "D:\"
    public int BenchSizeMB = 1024;
    public int BenchSeconds = 8;      // duração de cada teste aleatório 4K
    public string Phase = "";
    public double SeqReadMBs, SeqWriteMBs, RndReadMBs, RndWriteMBs, RndReadIops, RndWriteIops;

    // Teste de capacidade real (modo "fakecheck") - detecta pendrives/cartões com capacidade falsificada
    public int FakeSamples = 4096;
    public int FakeChecked, FakeBad;
    public long FakeFirstBad = -1;     // posição (bytes) da primeira amostra que não voltou igual

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint protect);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualFree(IntPtr addr, UIntPtr size, uint type);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadFile(SafeFileHandle h, IntPtr buf, int n, out int done, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteFile(SafeFileHandle h, IntPtr buf, int n, out int done, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFilePointerEx(SafeFileHandle h, long dist, out long newPos, uint method);

    public long Done, Total, Mismatch;
    public int Errors, Slow;
    public int PatternFirst = -1;
    public volatile bool Running, Cancel, Pause;   // Pause: proteção térmica (o PowerShell liga/desliga)
    public string Error;
    public DateTime Started, Finished;
    public List<long> ErrorOffsets = new List<long>();
    public double[] Curve = new double[SEGMENTS];   // MB/s por faixa de 0,5% do disco
    double[] segBytes = new double[SEGMENTS], segSec = new double[SEGMENTS];

    // Lê o log de saúde NVMe (página 02h) direto pelo Windows (IOCTL_STORAGE_QUERY_PROPERTY,
    // StorageDeviceProtocolSpecificProperty). Funciona inclusive atrás do Intel RST/VMD, onde o smartctl falha.
    // Somente leitura. Retorna os 512 bytes do log ou null.
    public static byte[] ReadNvmeHealthLog(int disk)
    {
        const int SPSD = 40, LOG = 512;
        using (SafeFileHandle h = CreateFile(@"\\.\PhysicalDrive" + disk, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_RW,
                                             IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero))
        {
            if (h.IsInvalid) return null;
            byte[] b = new byte[8 + SPSD + LOG];
            BitConverter.GetBytes(50).CopyTo(b, 0);     // StorageDeviceProtocolSpecificProperty
            BitConverter.GetBytes(0).CopyTo(b, 4);      // PropertyStandardQuery
            BitConverter.GetBytes(3).CopyTo(b, 8);      // ProtocolTypeNvme
            BitConverter.GetBytes(2).CopyTo(b, 12);     // NVMeDataTypeLogPage
            BitConverter.GetBytes(2).CopyTo(b, 16);     // log 02h - SMART / Health Information
            BitConverter.GetBytes(SPSD).CopyTo(b, 24);  // ProtocolDataOffset
            BitConverter.GetBytes(LOG).CopyTo(b, 28);   // ProtocolDataLength
            int ret;
            if (!DeviceIoControlBytes(h, 0x002D1400, b, b.Length, b, b.Length, out ret, IntPtr.Zero)) return null;
            int off = BitConverter.ToInt32(b, 8 + 16);
            if (off <= 0 || 8 + off + LOG > b.Length) return null;
            byte[] log = new byte[LOG];
            Array.Copy(b, 8 + off, log, 0, LOG);
            int kelvin = BitConverter.ToUInt16(log, 1);
            if (kelvin < 200 || kelvin > 400) return null;   // resposta sem sentido: descarta
            return log;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "DeviceIoControl")]
    static extern bool DeviceIoControlBytes(SafeFileHandle h, uint code, byte[] inBuf, int inSize,
                                            byte[] outBuf, int outSize, out int returned, IntPtr overlapped);

    public void Start()
    {
        Running = true;
        Started = DateTime.Now;
        Thread t = new Thread(Run);
        t.IsBackground = true;
        t.Start();
    }

    void Run()
    {
        try
        {
            if (DiskSize <= 0 && Mode != "erase" && Mode != "bench")
                throw new IOException("O disco informa capacidade de 0 bytes (sem mídia ou com defeito). Nada foi feito.");
            switch (Mode)
            {
                case "bench":        DoBench(); break;
                case "fakecheck":    DoFakeCheck(); break;
                case "zero":         DoWrite(); break;
                case "read":         DoScan(false, false); break;
                case "sample":       DoScan(true, false); break;
                case "verify":       DoScan(false, true); break;
                case "verifysample": DoScan(true, true); break;
                case "erase":        DoErase(); break;
                case "repair":       DoRepair(); break;
                default: throw new ArgumentException("Modo inválido: " + Mode);
            }
        }
        catch (Exception ex) { Error = ex.Message; }
        finally { Finished = DateTime.Now; Running = false; }
    }

    SafeFileHandle Open(bool write)
    {
        SafeFileHandle h = CreateFile(@"\\.\PhysicalDrive" + Disk,
            write ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_READ, FILE_SHARE_RW, IntPtr.Zero,
            OPEN_EXISTING, write ? FILE_FLAG_WRITE_THROUGH : 0, IntPtr.Zero);
        if (h.IsInvalid)
            throw new IOException("Não foi possível abrir o disco (erro Win32 " + Marshal.GetLastWin32Error() + ").");
        return h;
    }

    void Record(int seg, long bytes, double sec)
    {
        if (seg < 0) seg = 0;
        if (seg >= SEGMENTS) seg = SEGMENTS - 1;
        segBytes[seg] += bytes;
        segSec[seg] += sec;
        if (segSec[seg] > 0) Curve[seg] = segBytes[seg] / segSec[seg] / 1048576.0;
    }

    void WaitIfPaused()
    {
        while (Pause && !Cancel) Thread.Sleep(500);
    }

    static bool AllEqual(byte[] b, int n, byte v)
    {
        ulong pat = v * 0x0101010101010101UL;
        int i = 0;
        for (; i + 8 <= n; i += 8)
            if (BitConverter.ToUInt64(b, i) != pat) return false;
        for (; i < n; i++)
            if (b[i] != v) return false;
        return true;
    }

    // Sobrescreve o disco inteiro com zeros, em blocos de 4 MB.
    void DoWrite()
    {
        Total = DiskSize;
        byte[] buf = new byte[4 << 20];
        Stopwatch sw = new Stopwatch();
        using (SafeFileHandle h = Open(true))
        using (FileStream fs = new FileStream(h, FileAccess.ReadWrite, 1, false))
        {
            while (Done < Total && !Cancel)
            {
                WaitIfPaused();
                if (Cancel) break;
                int n = (int)Math.Min(buf.Length, Total - Done);
                sw.Restart();
                fs.Write(buf, 0, n);
                sw.Stop();
                Record((int)(Done * SEGMENTS / Total), n, sw.Elapsed.TotalSeconds);
                Done += n;
            }
            fs.Flush();
        }
        if (!Cancel && Done < Total)
            throw new IOException("Gravação incompleta: " + Done + " de " + Total + " bytes.");
    }

    // Leitura completa ou por amostragem; com check=true confere o conteúdo
    // (completa: tudo deve ser 0x00; amostragem: todos os blocos com o mesmo byte).
    void DoScan(bool sample, bool check)
    {
        const int CH = 1 << 20;
        byte[] buf = new byte[CH];
        long step = CH;
        int count = 0;
        if (sample)
        {
            step = (DiskSize / Samples) / CH * CH;
            if (step < CH) step = CH;
            count = (int)Math.Min(Samples, DiskSize / step);
            Total = (long)count * CH;
        }
        else
        {
            Total = DiskSize;
            if (check) PatternFirst = 0;
        }

        Stopwatch sw = new Stopwatch();
        using (SafeFileHandle h = Open(false))
        using (FileStream fs = new FileStream(h, FileAccess.Read, 1, false))
        {
            long k = 0;
            while (Done < Total && !Cancel)
            {
                WaitIfPaused();
                if (Cancel) break;
                long pos = sample ? k * step : Done;
                int n = (int)Math.Min(CH, DiskSize - pos);
                if (n <= 0) break;
                bool ok = true;
                sw.Restart();
                try
                {
                    fs.Position = pos;
                    int got = 0;
                    while (got < n)
                    {
                        int r = fs.Read(buf, got, n - got);
                        if (r <= 0) break;
                        got += r;
                    }
                    if (got < n) throw new IOException("Leitura incompleta");
                }
                catch (IOException)
                {
                    ok = false;
                    Errors++;
                    if (ErrorOffsets.Count < 5000) ErrorOffsets.Add(pos);
                }
                sw.Stop();
                if (ok && check)
                {
                    if (PatternFirst < 0) PatternFirst = buf[0];
                    if (!AllEqual(buf, n, (byte)PatternFirst)) Mismatch++;
                }
                if (sw.ElapsedMilliseconds > 300) Slow++;
                int seg = sample ? (int)(k * SEGMENTS / count) : (int)(pos * SEGMENTS / DiskSize);
                Record(seg, n, sw.Elapsed.TotalSeconds);
                Done += n;
                k++;
            }
        }
    }

    // Pede ao controlador/driver que apague a mídia (IOCTL_STORAGE_REINITIALIZE_MEDIA, Windows 10 2004+).
    void DoErase()
    {
        Total = 1;
        using (SafeFileHandle h = Open(true))
        {
            STORAGE_REINITIALIZE_MEDIA r = new STORAGE_REINITIALIZE_MEDIA();
            r.Version = 16; r.Size = 16; r.TimeoutInSeconds = 900; r.SanitizeOption = 0;
            int ret;
            if (!DeviceIoControl(h, IOCTL_STORAGE_REINITIALIZE_MEDIA, ref r, 16, IntPtr.Zero, 0, out ret, IntPtr.Zero))
            {
                int e = Marshal.GetLastWin32Error();
                if (e == 1 || e == 50 || e == 87)
                    throw new NotSupportedException("O disco/driver não aceita apagamento pelo controlador (erro " + e +
                                                    "). Use o modo Completo ou a ferramenta do fabricante.");
                throw new IOException("Falha no apagamento pelo controlador (erro Win32 " + e + ").");
            }
        }
        Done = 1;
    }

    static bool TryRead(FileStream fs, long pos, byte[] buf, int n)
    {
        try
        {
            fs.Position = pos;
            int got = 0;
            while (got < n)
            {
                int r = fs.Read(buf, got, n - got);
                if (r <= 0) break;
                got += r;
            }
            return got == n;
        }
        catch (IOException) { return false; }
    }

    // Procura, setor a setor, os setores ilegíveis dentro dos blocos informados e grava zeros
    // somente neles - isso força o HDD a substituí-los por setores reserva. Depois relê para confirmar.
    void DoRepair()
    {
        const int CH = 1 << 20;
        int ss = SectorSize < 512 ? 512 : SectorSize;
        Total = (long)RepairBlocks.Count * CH;
        List<SafeFileHandle> locks = new List<SafeFileHandle>();
        try
        {
            if (VolumeLetters != null)
            {
                foreach (string l in VolumeLetters)
                {
                    SafeFileHandle v = CreateFile(@"\\.\" + l + ":", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_RW,
                                                  IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                    if (v.IsInvalid)
                        throw new IOException("Não foi possível abrir a unidade " + l + ": (erro Win32 " + Marshal.GetLastWin32Error() + ").");
                    locks.Add(v);
                    int ret;
                    if (!DeviceIoControlSimple(v, FSCTL_LOCK_VOLUME, IntPtr.Zero, 0, IntPtr.Zero, 0, out ret, IntPtr.Zero))
                        throw new IOException("A unidade " + l + ": está em uso. Feche os programas e janelas que usam esse disco e tente de novo.");
                    DeviceIoControlSimple(v, FSCTL_DISMOUNT_VOLUME, IntPtr.Zero, 0, IntPtr.Zero, 0, out ret, IntPtr.Zero);
                }
            }
            byte[] sec = new byte[ss];
            byte[] zero = new byte[ss];
            using (SafeFileHandle h = Open(true))
            using (FileStream fs = new FileStream(h, FileAccess.ReadWrite, 1, false))
            {
                foreach (long blk in RepairBlocks)
                {
                    if (Cancel) break;
                    long end = Math.Min(blk + CH, DiskSize);
                    for (long pos = blk - (blk % ss); pos < end && !Cancel; pos += ss)
                    {
                        if (TryRead(fs, pos, sec, ss)) continue;
                        BadSectors++;
                        if (BadSectorOffsets.Count < 5000) BadSectorOffsets.Add(pos);
                        try { fs.Position = pos; fs.Write(zero, 0, ss); fs.Flush(); }
                        catch (IOException) { }
                        if (TryRead(fs, pos, sec, ss)) FixedSectors++; else StillBad++;
                    }
                    Done += CH;
                }
            }
        }
        finally
        {
            foreach (SafeFileHandle v in locks) v.Dispose();   // destrava e o Windows remonta a unidade
        }
    }

    void BenchSeek(SafeFileHandle h, long pos)
    {
        long np;
        if (!SetFilePointerEx(h, pos, out np, 0)) throw new IOException("Falha ao posicionar (erro " + Marshal.GetLastWin32Error() + ").");
    }

    void BenchIO(SafeFileHandle h, IntPtr buf, int n, bool write)
    {
        int got;
        bool ok = write ? WriteFile(h, buf, n, out got, IntPtr.Zero) : ReadFile(h, buf, n, out got, IntPtr.Zero);
        if (!ok || got != n) throw new IOException((write ? "Falha de gravação" : "Falha de leitura") + " no benchmark (erro " + Marshal.GetLastWin32Error() + ").");
    }

    // Sequencial 8 MB e aleatório 4K (fila 1), sem cache do Windows (FILE_FLAG_NO_BUFFERING).
    void DoBench()
    {
        const uint NO_BUFFERING = 0x20000000, DELETE_ON_CLOSE = 0x04000000, TEMPORARY = 0x100, CREATE_ALWAYS = 2;
        const int SEQ = 8 << 20, RND = 4096;
        long size = (long)BenchSizeMB << 20;
        Total = 400;
        string file = Path.Combine(BenchPath, "DiskTool_benchmark.tmp");
        IntPtr buf = VirtualAlloc(IntPtr.Zero, (UIntPtr)SEQ, 0x3000, 0x04);
        if (buf == IntPtr.Zero) throw new OutOfMemoryException("Sem memória para o benchmark.");
        try
        {
            byte[] rnd = new byte[SEQ];
            new Random().NextBytes(rnd);               // dados aleatórios: evita compressão do controlador
            Marshal.Copy(rnd, 0, buf, SEQ);
            using (SafeFileHandle h = CreateFile(file, GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, CREATE_ALWAYS,
                                                 NO_BUFFERING | DELETE_ON_CLOSE | TEMPORARY, IntPtr.Zero))
            {
                if (h.IsInvalid) throw new IOException("Não foi possível criar o arquivo de teste (erro " + Marshal.GetLastWin32Error() + ").");
                Stopwatch sw = new Stopwatch();

                Phase = "Gravação sequencial";
                BenchSeek(h, 0); sw.Restart();
                for (long p = 0; p < size && !Cancel; p += SEQ) { WaitIfPaused(); BenchIO(h, buf, SEQ, true); Done = p * 100 / size; }
                SeqWriteMBs = size / 1048576.0 / sw.Elapsed.TotalSeconds;
                if (Cancel) return;

                Phase = "Leitura sequencial";
                BenchSeek(h, 0); sw.Restart();
                for (long p = 0; p < size && !Cancel; p += SEQ) { WaitIfPaused(); BenchIO(h, buf, SEQ, false); Done = 100 + p * 100 / size; }
                SeqReadMBs = size / 1048576.0 / sw.Elapsed.TotalSeconds;
                if (Cancel) return;

                Random r = new Random();
                long blocks = size / RND;
                for (int pass = 0; pass < 2 && !Cancel; pass++)
                {
                    bool write = pass == 1;
                    Phase = write ? "Gravação aleatória 4K" : "Leitura aleatória 4K";
                    long ops = 0; sw.Restart();
                    while (sw.Elapsed.TotalSeconds < BenchSeconds && !Cancel)
                    {
                        long b = (long)(r.NextDouble() * blocks);
                        BenchSeek(h, b * RND);
                        BenchIO(h, buf, RND, write);
                        ops++;
                        Done = 200 + pass * 100 + (long)(sw.Elapsed.TotalSeconds * 100 / BenchSeconds);
                    }
                    double secs = sw.Elapsed.TotalSeconds;
                    if (write) { RndWriteIops = ops / secs; RndWriteMBs = ops * RND / 1048576.0 / secs; }
                    else       { RndReadIops = ops / secs;  RndReadMBs = ops * RND / 1048576.0 / secs; }
                }
                Done = Total;
            }
        }
        finally { VirtualFree(buf, UIntPtr.Zero, 0x8000); }
    }

    // Monta o bloco de assinatura da amostra k: identificador da sessão + posição + dados derivados dela.
    static void FillSignature(byte[] b, byte[] session, long pos, int k)
    {
        Random r = new Random(k * 7919 + (int)(pos & 0x7FFFFFFF));
        r.NextBytes(b);
        Buffer.BlockCopy(session, 0, b, 0, 16);
        Buffer.BlockCopy(BitConverter.GetBytes(pos), 0, b, 16, 8);
        Buffer.BlockCopy(BitConverter.GetBytes(k), 0, b, 24, 4);
    }

    // Grava blocos de 4 KB assinados espalhados por todo o disco e depois relê todos.
    // Pendrive falsificado "dá a volta": gravar no fim sobrescreve o começo, e as amostras não conferem.
    void DoFakeCheck()
    {
        const int BS = 4096;
        long blocks = DiskSize / BS;
        int n = (int)Math.Min(FakeSamples, blocks);
        if (n < 2) throw new IOException("Disco pequeno demais para o teste.");
        long[] pos = new long[n];
        for (int k = 0; k < n; k++) pos[k] = (blocks - 1) * k / (n - 1) * BS;
        byte[] session = Guid.NewGuid().ToByteArray();
        byte[] sig = new byte[BS], got = new byte[BS];
        Total = 2L * n;
        using (SafeFileHandle h = Open(true))
        using (FileStream fs = new FileStream(h, FileAccess.ReadWrite, 1, false))
        {
            Phase = "Gravando amostras";
            for (int k = 0; k < n && !Cancel; k++)
            {
                FillSignature(sig, session, pos[k], k);
                try { fs.Position = pos[k]; fs.Write(sig, 0, BS); }
                catch (IOException) { }               // falha de gravação aparece na releitura
                Done = k + 1;
            }
            fs.Flush();
            if (Cancel) return;
            Phase = "Conferindo amostras";
            for (int k = 0; k < n && !Cancel; k++)
            {
                FillSignature(sig, session, pos[k], k);
                bool ok = TryRead(fs, pos[k], got, BS);
                if (ok)
                    for (int i = 0; i < BS; i++) if (got[i] != sig[i]) { ok = false; break; }
                if (!ok) { FakeBad++; if (FakeFirstBad < 0 || pos[k] < FakeFirstBad) FakeFirstBad = pos[k]; }
                FakeChecked++;
                Done = n + k + 1;
            }
        }
    }
}

// Avisa quando um disco/pendrive é conectado ou removido (WM_DEVICECHANGE).
public class DeviceWatcher : System.Windows.Forms.NativeWindow
{
    public static volatile int Changes;
    protected override void WndProc(ref System.Windows.Forms.Message m)
    {
        if (m.Msg == 0x0219)
        {
            int w = m.WParam.ToInt32();
            if (w == 0x8000 || w == 0x8004 || w == 0x0007) Changes++;   // chegada, remoção, nós alterados
        }
        base.WndProc(ref m);
    }
}
'@ -ReferencedAssemblies System.Windows.Forms
}

# ---------------------------------------------------------------- Utilidades
# Remove caracteres de controle/invisíveis que alguns pendrives e adaptadores USB devolvem no serial.
function Get-CleanSerial($s) { return (("$s" -replace '[\x00-\x1F\x7F]', '').Trim()) }

function Format-Size([double]$b) {
    if ($b -ge 1e12) { return '{0:N2} TB' -f ($b / 1e12) }
    if ($b -ge 1e9)  { return '{0:N1} GB' -f ($b / 1e9) }
    return '{0:N0} MB' -f ($b / 1e6)
}

function Format-Duration([double]$sec) {
    if ($sec -lt 0) { $sec = 0 }
    $t = [TimeSpan]::FromSeconds([Math]::Round($sec))
    return '{0:00}:{1:00}:{2:00}' -f [Math]::Floor($t.TotalHours), $t.Minutes, $t.Seconds
}

function Show-Value($v, [string]$suffix = '') {
    if ($null -eq $v -or "$v" -eq '') { return 'n/d' }
    return "$v$suffix"
}

function Invoke-Diskpart([string[]]$lines) {
    $tmp = Join-Path $env:TEMP ("disktool_{0}.txt" -f [guid]::NewGuid())
    Set-Content -Path $tmp -Value $lines -Encoding ASCII
    try {
        $out = & diskpart.exe /s $tmp | Out-String
        if ($LASTEXITCODE -ne 0) { throw "diskpart falhou: $out" }
        return $out
    } finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
}

function Find-Smartctl {
    $c = Get-Command smartctl.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    foreach ($p in @((Join-Path $ScriptDir 'smartctl.exe'),
                     (Join-Path $ScriptDir 'smartmontools\bin\smartctl.exe'),
                     "$env:ProgramFiles\smartmontools\bin\smartctl.exe",
                     "${env:ProgramFiles(x86)}\smartmontools\bin\smartctl.exe")) {
        if ($p -and (Test-Path $p)) { return $p }
    }
    return $null
}
$SmartctlPath = Find-Smartctl

# ---------------------------------------------------------------- Configurações (empresa / técnico / logo)
function Get-Settings {
    $s = [pscustomobject]@{ Empresa = ''; Contato = ''; Tecnico = ''; Logo = ''; MonitorTime = '09:00'; Theme = 'Sistema'; Bancada = $false }
    if (Test-Path $SettingsFile) {
        try {
            $j = Get-Content $SettingsFile -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($k in 'Empresa', 'Contato', 'Tecnico', 'Logo', 'MonitorTime', 'Theme') { if ($j.$k) { $s.$k = [string]$j.$k } }
            if ($j.Bancada -eq $true) { $s.Bancada = $true }
        } catch { }
    }
    return $s
}
function Save-Settings($s) {
    [IO.File]::WriteAllText($SettingsFile, ($s | ConvertTo-Json), (New-Object Text.UTF8Encoding($true)))
}
$Settings = Get-Settings

# ---------------------------------------------------------------- SMART via smartctl (opcional)
function Invoke-Smartctl([string[]]$arguments) {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { return (& $SmartctlPath @arguments 2>$null | Out-String) }
    catch { return '' }
    finally { $ErrorActionPreference = $old }
}

function Get-SmartctlJson([int]$num, [string]$tipo, [int64]$size) {
    if (-not $SmartctlPath) { return $null }
    $sets = @(, @("/dev/pd$num"))
    if ($tipo -eq 'NVMe') { $sets = @(@('-d', 'nvme', "/dev/pd$num"), @("/dev/pd$num")) }
    $lastErr = $null
    foreach ($dev in $sets) {
        $raw = Invoke-Smartctl (@('-j', '-x') + $dev)
        if (-not $raw) { continue }
        try { $j = $raw | ConvertFrom-Json } catch { continue }
        if (-not $j -or -not $j.device) { continue }
        # Só aceita se o smartctl realmente leu o disco (bit 1 = falha ao abrir/identificar)
        $hasData = $j.nvme_smart_health_information_log -or $j.ata_smart_attributes -or $j.smart_status
        if (([int]$j.smartctl.exit_status -band 2) -or -not $hasData) {
            $lastErr = (@($j.smartctl.messages | ForEach-Object { $_.string }) -join ' ')
            continue
        }
        $cap = $null
        if ($j.user_capacity -and $j.user_capacity.bytes) { $cap = [double]$j.user_capacity.bytes }
        elseif ($j.nvme_total_capacity) { $cap = [double]$j.nvme_total_capacity }
        if ($cap -and $size -and [Math]::Abs($cap - $size) -gt 0.02 * $size) { continue }   # outro disco: ignora
        return @{ Json = $j; DevArgs = $dev }
    }
    if (-not $lastErr) { $lastErr = 'sem resposta do disco' }
    return @{ Error = $lastErr }
}

# Converte o log de saúde NVMe lido pelo Windows no mesmo formato JSON do smartctl,
# para reaproveitar Merge-SmartctlData, a tabela SMART e o cálculo de durabilidade.
function Get-NvmeHealthNative([int]$num) {
    $l = $null
    try { $l = [DiskJob]::ReadNvmeHealthLog($num) } catch { }
    if (-not $l) { return $null }
    $u64 = { param($o) [double][BitConverter]::ToUInt64($l, $o) }
    $temp = [BitConverter]::ToUInt16($l, 1) - 273
    $log = [pscustomobject]@{
        critical_warning = [int]$l[0]; temperature = $temp; available_spare = [int]$l[3]; available_spare_threshold = [int]$l[4]
        percentage_used = [int]$l[5]; data_units_read = (& $u64 32); data_units_written = (& $u64 48)
        host_reads = (& $u64 64); host_writes = (& $u64 80); controller_busy_time = (& $u64 96); power_cycles = (& $u64 112)
        power_on_hours = (& $u64 128); unsafe_shutdowns = (& $u64 144); media_errors = (& $u64 160); num_err_log_entries = (& $u64 176)
    }
    return [pscustomobject]@{
        nvme_smart_health_information_log = $log
        temperature = [pscustomobject]@{ current = $temp }
        power_on_time = [pscustomobject]@{ hours = $log.power_on_hours }
        power_cycle_count = $log.power_cycles
        smart_status = [pscustomobject]@{ passed = ($log.critical_warning -eq 0) }
    }
}

# Intel RST/VMD (iaStorVD/iaStorAC) não repassa comandos SMART/NVMe de programas externos.
$RstController = $null
try {
    $RstController = Get-CimInstance Win32_SCSIController -ErrorAction Stop |
        Where-Object { $_.DriverName -match '^iaStor' -or $_.Name -match 'RST|VMD' } | Select-Object -First 1
} catch { }

function Merge-SmartctlData($info, $j) {
    $failed = @()
    if ($j.smart_status -and $null -ne $j.smart_status.passed) { $info.SmartPassed = [bool]$j.smart_status.passed }
    if ($j.power_on_time -and $j.power_on_time.hours) { $info.PowerOnHours = [int64]$j.power_on_time.hours }
    if ($j.temperature -and $j.temperature.current) { $info.Temp = [int]$j.temperature.current }

    $n = $j.nvme_smart_health_information_log
    if ($n) {
        $info.Wear            = [int]$n.percentage_used
        $info.Spare           = [int]$n.available_spare
        $info.SpareThresh     = [int]$n.available_spare_threshold
        $info.MediaErrors     = [int64]$n.media_errors
        $info.UnsafeShutdowns = [int64]$n.unsafe_shutdowns
        $info.CriticalWarning = [int]$n.critical_warning
        $info.TBW             = [Math]::Round([double]$n.data_units_written * 512000 / 1e12, 2)
        if (-not $info.PowerOnHours -and $n.power_on_hours) { $info.PowerOnHours = [int64]$n.power_on_hours }
    }

    if ($n) { $info.TBR = [Math]::Round([double]$n.data_units_read * 512000 / 1e12, 2) }

    # Dados gerais (estilo CrystalDiskInfo)
    if ($null -ne $j.power_cycle_count) { $info.PowerCycles = [int64]$j.power_cycle_count }
    elseif ($n -and $null -ne $n.power_cycles) { $info.PowerCycles = [int64]$n.power_cycles }
    if ($null -ne $j.rotation_rate) { $info.Rpm = [int]$j.rotation_rate }
    if ($j.nvme_version) { $info.Standard = "NVMe $($j.nvme_version.string)" }
    elseif ($j.sata_version) { $info.Standard = "$($j.ata_version.string) | $($j.sata_version.string)".Trim(' |') }
    if ($j.interface_speed -and $j.interface_speed.current) { $info.LinkSpeed = [string]$j.interface_speed.current.string }
    $feat = @()
    if ($j.smart_support -and $j.smart_support.available) { $feat += 'S.M.A.R.T.' }
    if ($j.trim -and $j.trim.supported) { $feat += 'TRIM' }
    if ($j.ata_security -and $j.ata_security.enabled) { $feat += 'Senha ATA ativa' }
    if ($n) { $feat += 'Log de saúde NVMe' }
    $info.Features = ($feat -join ', ')
    $info.SmartJson = $j

    $wearAttr = $null
    $lbs = 512; if ($j.logical_block_size) { $lbs = [int]$j.logical_block_size }
    $attrWritten = $null; $attrRead = $null
    if ($j.ata_smart_attributes -and $j.ata_smart_attributes.table) {
        foreach ($a in $j.ata_smart_attributes.table) {
            $raw = [int64]$a.raw.value
            switch ([int]$a.id) {
                5   { $info.Realloc = $raw }
                197 { $info.Pending = $raw }
                198 { $info.Uncorr = $raw }
                199 { $info.CRC = $raw }
                187 { $info.ReportedUncorr = $raw }
            }
            # Vida útil restante (valor normalizado) - o nome varia por fabricante
            if ($info.Tipo -eq 'SSD' -and $a.name -match 'Wear_Leveling|Wearout|Life_Left|Lifetime_Remain|Percent_Lifetime|SSD_Life') {
                $wearAttr = [Math]::Max(0, 100 - [int]$a.value)
            }
            # Total gravado/lido pelo computador: a unidade do valor bruto depende do fabricante
            $mult = $null
            if ($a.name -match '32MiB') { $mult = 32MB } elseif ($a.name -match 'GiB') { $mult = 1GB }
            elseif ($a.name -match 'MiB') { $mult = 1MB } elseif ($a.name -match 'LBA|Sector') { $mult = $lbs }
            if ($mult) {
                if ([int]$a.id -in 241, 246 -and $a.name -match 'Writ') { $attrWritten = [double]$raw * $mult / 1e12 }
                if ([int]$a.id -in 242 -and $a.name -match 'Read') { $attrRead = [double]$raw * $mult / 1e12 }
            }
            if ($a.when_failed) { $failed += "Atributo SMART '$($a.name)' abaixo do limite do fabricante ($($a.when_failed))" }
        }
    }
    if ($null -ne $attrWritten) { $info.TBW = [Math]::Round($attrWritten, 2) }
    if ($null -ne $attrRead) { $info.TBR = [Math]::Round($attrRead, 2) }
    $wearStat = $null
    if ($j.ata_device_statistics -and $j.ata_device_statistics.pages) {
        foreach ($p in $j.ata_device_statistics.pages) {
            foreach ($e in $p.table) {
                if ($e.name -match 'Percentage Used Endurance') { $wearStat = [int]$e.value }
                elseif ($e.name -match 'Logical Sectors Written') { $info.TBW = [Math]::Round([double]$e.value * $lbs / 1e12, 2) }
                elseif ($e.name -match 'Logical Sectors Read') { $info.TBR = [Math]::Round([double]$e.value * $lbs / 1e12, 2) }
            }
        }
    }
    if ($info.Tipo -eq 'SSD') {
        if ($null -ne $wearStat) { $info.Wear = $wearStat } elseif ($null -ne $wearAttr) { $info.Wear = $wearAttr }
    }
    $info.SmartFailedAttrs = $failed
    $info.SmartSource = 'smartctl'
}

# ---------------------------------------------------------------- Durabilidade (TBW)
# TBW garantido pelo fabricante (ficha técnica), por modelo e capacidade nominal em GB.
# Confira sempre a ficha do seu modelo: o fabricante pode mudar a especificação entre revisões.
$TbwTable = @(
    @{ Name = 'Samsung 990 PRO';        Match = '990 PRO';                       Tbw = @{ 1000 = 600; 2000 = 1200; 4000 = 2400 } }
    @{ Name = 'Samsung 990 EVO';        Match = '990 EVO';                       Tbw = @{ 1000 = 600; 2000 = 1200 } }
    @{ Name = 'Samsung 980 PRO';        Match = '980 PRO';                       Tbw = @{ 250 = 150; 500 = 300; 1000 = 600; 2000 = 1200 } }
    @{ Name = 'Samsung 980';            Match = 'Samsung SSD 980 (?!PRO)';       Tbw = @{ 250 = 150; 500 = 300; 1000 = 600 } }
    @{ Name = 'Samsung 970 EVO Plus';   Match = '970 EVO Plus';                  Tbw = @{ 250 = 150; 500 = 300; 1000 = 600; 2000 = 1200 } }
    @{ Name = 'Samsung 870 EVO';        Match = '870 EVO';                       Tbw = @{ 250 = 150; 500 = 300; 1000 = 600; 2000 = 1200; 4000 = 2400 } }
    @{ Name = 'Samsung 860 EVO';        Match = '860 EVO';                       Tbw = @{ 250 = 150; 500 = 300; 1000 = 600; 2000 = 1200; 4000 = 2400 } }
    @{ Name = 'Crucial MX500';          Match = 'MX500';                         Tbw = @{ 250 = 100; 500 = 180; 1000 = 360; 2000 = 700; 4000 = 1000 } }
    @{ Name = 'Crucial BX500';          Match = 'BX500';                         Tbw = @{ 120 = 40; 240 = 80; 480 = 120; 1000 = 360; 2000 = 720 } }
    @{ Name = 'Crucial P5 Plus';        Match = 'P5PSSD';                        Tbw = @{ 500 = 300; 1000 = 600; 2000 = 1200 } }
    @{ Name = 'Crucial P3 Plus';        Match = 'P3PSSD';                        Tbw = @{ 500 = 110; 1000 = 220; 2000 = 440; 4000 = 800 } }
    @{ Name = 'Crucial P3';             Match = 'P3SSD';                         Tbw = @{ 500 = 110; 1000 = 220; 2000 = 440; 4000 = 800 } }
    @{ Name = 'Kingston A400';          Match = 'SA400';                         Tbw = @{ 120 = 40; 240 = 80; 480 = 160; 960 = 300; 1920 = 600 } }
    @{ Name = 'Kingston NV2';           Match = 'SNV2S';                         Tbw = @{ 250 = 80; 500 = 160; 1000 = 320; 2000 = 640; 4000 = 1280 } }
    @{ Name = 'Kingston NV3';           Match = 'SNV3S';                         Tbw = @{ 500 = 160; 1000 = 320; 2000 = 640; 4000 = 1280 } }
    @{ Name = 'Kingston KC3000';        Match = 'SKC3000';                       Tbw = @{ 512 = 400; 1024 = 800; 2048 = 1600; 4096 = 3200 } }
    @{ Name = 'Kingston FURY Renegade'; Match = 'SFYR';                          Tbw = @{ 500 = 500; 1000 = 1000; 2000 = 2000; 4000 = 4000 } }
    @{ Name = 'WD Black SN850X';        Match = 'SN850X|WDS\d+T?\d*X0E';         Tbw = @{ 1000 = 600; 2000 = 1200; 4000 = 2400 } }
    @{ Name = 'WD Blue SN580';          Match = 'SN580|WDS\w+3B0E';              Tbw = @{ 250 = 150; 500 = 300; 1000 = 600; 2000 = 900 } }
    @{ Name = 'WD Blue SN570';          Match = 'SN570|WDS\w+3B0C';              Tbw = @{ 250 = 150; 500 = 300; 1000 = 600; 2000 = 900 } }
    @{ Name = 'WD Blue 3D (SATA)';      Match = 'WDS\w+2B0A';                    Tbw = @{ 250 = 100; 500 = 200; 1000 = 400; 2000 = 500; 4000 = 600 } }
)
$TbwCustomFile = Join-Path $ScriptDir 'TBW_personalizado.json'

function Get-CustomTbw {
    $h = @{}
    if (Test-Path $TbwCustomFile) {
        try { (Get-Content $TbwCustomFile -Raw -Encoding UTF8 | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $h[$_.Name] = [double]$_.Value } } catch { }
    }
    return $h
}

function Set-CustomTbw([string]$model, $tb) {
    $h = Get-CustomTbw
    if ($null -eq $tb) { $h.Remove($model) } else { $h[$model] = [double]$tb }
    [IO.File]::WriteAllText($TbwCustomFile, ([pscustomobject]$h | ConvertTo-Json), (New-Object Text.UTF8Encoding($true)))
}

function Get-RatedTbw($i) {
    $custom = Get-CustomTbw
    if ($custom.ContainsKey($i.Model)) { return @{ TB = $custom[$i.Model]; Source = 'informado por você (TBW_personalizado.json)' } }
    $gb = $i.Size / 1e9
    foreach ($row in $TbwTable) {
        if ($i.Model -notmatch $row.Match) { continue }
        $best = $null
        foreach ($cap in $row.Tbw.Keys) { if ([Math]::Abs($gb - $cap) / $cap -le 0.12 -and (-not $best -or [Math]::Abs($gb - $cap) -lt [Math]::Abs($gb - $best))) { $best = $cap } }
        if ($best) { return @{ TB = [double]$row.Tbw[$best]; Source = "ficha do fabricante - $($row.Name) $best GB (tabela do DiskTool)" } }
    }
    # Fora da tabela: o próprio disco informa a % de vida usada; TBW ≈ gravado ÷ % usado
    if ($i.Tipo -ne 'HDD' -and $i.TBW -gt 0 -and $i.Wear -ge 3) {
        return @{ TB = [Math]::Round($i.TBW / ($i.Wear / 100)); Source = "estimado pelo desgaste que o disco informa ($($i.Wear)% usado) - confira a ficha do fabricante"; Estimated = $true }
    }
    return $null
}

# Calcula o resumo de durabilidade (estilo CrystalDiskInfo + TBW) e grava os campos no objeto do disco.
function Update-Durability($i, $hist) {
    $i.HealthPct = $null; $i.RatedTBW = $null; $i.RatedSource = $null; $i.TbwUsedPct = $null
    $i.WriteRateTBDay = $null; $i.RateSource = $null; $i.RemainingYears = $null
    $i.RemainingYearsTbw = $null; $i.RemainingYearsWear = $null; $i.RemainingBasis = $null; $i.WearNote = $null
    if ($i.Size -le 0 -or $i.Tipo -eq 'HDD') { return }
    $r = Get-RatedTbw $i
    if ($r) {
        $i.RatedTBW = $r.TB; $i.RatedSource = $r.Source
        if ($null -ne $i.TBW -and $r.TB -gt 0) { $i.TbwUsedPct = [Math]::Round($i.TBW / $r.TB * 100, 1) }
    }
    if ($null -ne $i.Wear) { $i.HealthPct = [Math]::Max(0, 100 - [int]$i.Wear) }
    elseif ($null -ne $i.TbwUsedPct) { $i.HealthPct = [Math]::Max(0, [int][Math]::Round(100 - $i.TbwUsedPct)) }

    # Ritmo de gravação: pelo histórico (>= 7 dias) ou pela média desde novo (por dia ligado)
    $first = @($hist | Where-Object { $null -ne $_.TBGravados } | Select-Object -First 1)
    if ($first.Count -and $null -ne $i.TBW) {
        $days = ((Get-Date) - [datetime]$first[0].Data).TotalDays
        $delta = $i.TBW - [double]$first[0].TBGravados
        if ($days -ge 7 -and $delta -gt 0) { $i.WriteRateTBDay = $delta / $days; $i.RateSource = "histórico dos últimos $([int]$days) dias" }
    }
    if (-not $i.WriteRateTBDay -and $i.TBW -gt 0 -and $i.PowerOnHours -ge 168) {
        $i.WriteRateTBDay = $i.TBW / ($i.PowerOnHours / 24); $i.RateSource = 'média desde novo (por dia ligado)'
    }
    if ($i.RatedTBW -and $i.WriteRateTBDay -gt 0 -and $null -ne $i.TBW) {
        $i.RemainingYearsTbw = [Math]::Max(0, ($i.RatedTBW - $i.TBW) / $i.WriteRateTBDay / 365)
    }
    # Pelo desgaste real que o disco informa (inclui a amplificação de escrita do controlador)
    if ($null -ne $i.Wear -and $i.Wear -ge 2 -and $i.PowerOnHours -ge 168) {
        $perDay = $i.Wear / ($i.PowerOnHours / 24)
        if ($perDay -gt 0) { $i.RemainingYearsWear = [Math]::Max(0, (100 - $i.Wear) / $perDay / 365) }
    }
    # Vale a estimativa mais pessimista
    $cands = @($i.RemainingYearsTbw, $i.RemainingYearsWear | Where-Object { $null -ne $_ })
    if ($cands.Count) {
        $i.RemainingYears = ($cands | Measure-Object -Minimum).Minimum
        $i.RemainingBasis = $(if ($null -ne $i.RemainingYearsWear -and $i.RemainingYears -eq $i.RemainingYearsWear) { 'pelo desgaste real do disco, por dia ligado' } else { 'pelo TBW, no ritmo de gravação atual' })
    }
    if ($null -ne $i.Wear -and $null -ne $i.TbwUsedPct -and ($i.Wear - $i.TbwUsedPct) -ge 15) {
        $i.WearNote = ("O desgaste interno ({0}%) está bem acima do TBW consumido ({1:N1}%): o disco gasta a memória mais rápido " +
                       "do que o volume gravado sugere (amplificação de escrita). Use o desgaste como referência.") -f $i.Wear, $i.TbwUsedPct
    }
}

function Format-TB($v, [switch]$NoUnit) {
    if ($null -eq $v) { return 'n/d' }
    $d = [double]$v
    $s = if ($d -ge 100) { '{0:N0}' -f $d } elseif ($d -ge 10) { '{0:N1}' -f $d } else { '{0:N2}' -f $d }
    if ($NoUnit) { return $s }
    return "$s TB"
}

function Format-HealthLabel($i) {
    if ($null -ne $i.HealthPct -and $i.Verdict -notin 'Sem mídia', 'Sem dados') { return "$($i.Verdict) ($($i.HealthPct)%)" }
    return $i.Verdict
}

# ---------------------------------------------------------------- Histórico
function Get-DiskKey($i) {
    $k = (("$($i.Serial)" -replace '[^\w\-]', '_').Trim('_'))
    if (-not $k) { $k = ((("$($i.Model)_$($i.Size)") -replace '[^\w\-]', '_').Trim('_')) }
    return $k
}

function Get-HealthHistory($i) {
    $f = Join-Path $HistDir ((Get-DiskKey $i) + '.jsonl')
    if (-not (Test-Path $f)) { return @() }
    $all = @(Get-Content $f -Encoding UTF8 | Where-Object { $_.Trim() } | ForEach-Object { try { $_ | ConvertFrom-Json } catch { } })
    # Leituras "fracas" (só contadores do Windows, que erram desgaste/temperatura em vários NVMe) são descartadas
    # quando o disco já tem leituras reais (smartctl ou log NVMe) - senão o gráfico mostraria saltos falsos.
    $strong = @($all | Where-Object { -not (Test-WeakSnapshot $_) })
    if ($strong.Count) { return $strong }
    return $all
}

function Test-WeakSnapshot($s) {
    if ($s.Fonte) { return ($s.Fonte -eq 'Windows') }
    return ($null -eq $s.Horas -and $null -eq $s.TBGravados)   # leituras antigas, de antes do campo Fonte
}

$SnapFields = 'Desgaste', 'Horas', 'Realocados', 'Pendentes', 'Incorrigiveis', 'CRC', 'ErrosMidia', 'Spare', 'TBGravados', 'DesligInesperados', 'Diagnostico'

function Save-HealthSnapshot($i, $hist) {
    if ($i.Size -le 0 -or $i.Verdict -eq 'Sem mídia') { return }   # leitor vazio / pendrive com defeito: não gera histórico lixo
    $snap = [ordered]@{
        Data = (Get-Date).ToString('s'); Diagnostico = $i.Verdict; Temp = $i.Temp; Desgaste = $i.Wear
        Horas = $i.PowerOnHours; Realocados = $i.Realloc; Pendentes = $i.Pending; Incorrigiveis = $i.Uncorr
        CRC = $i.CRC; ErrosMidia = $i.MediaErrors; Spare = $i.Spare; TBGravados = $i.TBW
        DesligInesperados = $i.UnsafeShutdowns; Modelo = $i.Model; Fonte = $i.SmartSource
    }
    $last = $hist | Select-Object -Last 1
    if ((Test-WeakSnapshot $snap) -and $last -and -not (Test-WeakSnapshot $last)) { return }   # não polui um histórico com dados reais
    if ($last) {
        $age = ((Get-Date) - [datetime]$last.Data).TotalHours
        $same = ($SnapFields | ForEach-Object { "$($snap[$_])" -eq "$($last.$_)" }) -notcontains $false
        if ($same -and $age -lt 24) { return }
        if ($age -lt 1 -and "$($snap.Diagnostico)" -eq "$($last.Diagnostico)") { return }
    }
    try {
        if (-not (Test-Path $HistDir)) { New-Item -ItemType Directory -Path $HistDir | Out-Null }
        Add-Content -Path (Join-Path $HistDir ((Get-DiskKey $i) + '.jsonl')) -Value ($snap | ConvertTo-Json -Compress) -Encoding UTF8
    } catch { }
}

function Get-HistoryText($i) {
    $h = @(Get-HealthHistory $i)
    if (-not $h.Count) { return "Ainda não há histórico para este disco.`r`nCada vez que a lista é atualizada, uma leitura é salva em Historico\ (no máximo 1 por hora, ou 1 por dia se nada mudou)." }
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add("HISTÓRICO DE SAÚDE - Disco $($i.Number): $($i.Model)  (serial $($i.Serial))")
    $L.Add("$($h.Count) leitura(s) salva(s)")
    $L.Add('')
    $first = $h[0]; $last = $h[-1]
    if ($h.Count -gt 1) {
        $dias = [Math]::Max(1, [Math]::Round(([datetime]$last.Data - [datetime]$first.Data).TotalDays))
        $L.Add("Variação desde $(([datetime]$first.Data).ToString('dd/MM/yyyy')) ($dias dia(s)):")
        foreach ($p in @(@('Desgaste', 'Vida útil usada', ' pontos %'), @('Horas', 'Horas ligado', ' h'), @('TBGravados', 'Dados gravados', ' TB'),
                         @('Realocados', 'Setores realocados', ''), @('Pendentes', 'Setores pendentes', ''), @('Incorrigiveis', 'Setores incorrigíveis', ''),
                         @('ErrosMidia', 'Erros de mídia (NVMe)', ''), @('CRC', 'Erros de CRC (cabo)', ''), @('DesligInesperados', 'Desligamentos inesperados', ''))) {
            if ($null -ne $first.($p[0]) -and $null -ne $last.($p[0])) {
                $d = [double]$last.($p[0]) - [double]$first.($p[0])
                $sign = ''; if ($d -gt 0) { $sign = '+' }
                $L.Add(('   {0,-28} {1} -> {2}  ({3}{4}{5})' -f $p[1], $first.($p[0]), $last.($p[0]), $sign, $d, $p[2]))
            }
        }
        if ($null -ne $first.Desgaste -and $null -ne $last.Desgaste -and $last.Desgaste -gt $first.Desgaste) {
            $porDia = ($last.Desgaste - $first.Desgaste) / $dias
            $restante = [Math]::Round((100 - $last.Desgaste) / $porDia / 365, 1)
            $L.Add("   Estimativa: nesse ritmo, a vida útil nominal acaba em ~$restante ano(s).")
        }
        $L.Add('')
    }
    $f = '{0,-17} {1,-10} {2,5} {3,6} {4,8} {5,7} {6,6} {7,6} {8,9}'
    $L.Add(($f -f 'Data', 'Saúde', 'Temp', 'Desg%', 'Horas', 'Realoc', 'Pend', 'Mídia', 'TB grav.'))
    $L.Add(('-' * 84))
    foreach ($s in ($h | Select-Object -Last 200)) {
        $L.Add(($f -f ([datetime]$s.Data).ToString('dd/MM/yyyy HH:mm'), $s.Diagnostico, $s.Temp, $s.Desgaste, $s.Horas,
                      $s.Realocados, $s.Pendentes, $s.ErrosMidia, $s.TBGravados))
    }
    return ($L -join "`r`n")
}

# ---------------------------------------------------------------- Inventário e saúde
function Get-ProtectedDisks {
    $set = @{}
    foreach ($d in @(Get-Disk)) {
        if ($d.IsSystem -or $d.IsBoot) { $set[[int]$d.Number] = 'Disco do sistema / boot' }
    }
    $letters = @($env:SystemDrive.Substring(0, 1))
    try { Get-CimInstance Win32_PageFileUsage | ForEach-Object { $letters += $_.Name.Substring(0, 1) } } catch { }
    if ($ScriptDir -match '^([A-Za-z]):') { $letters += $Matches[1] }
    foreach ($l in ($letters | Select-Object -Unique)) {
        try {
            $n = [int](Get-Partition -DriveLetter $l -ErrorAction Stop).DiskNumber
            if (-not $set.ContainsKey($n)) { $set[$n] = "Contém a unidade $($l): (Windows, paginação ou o próprio DiskTool)" }
        } catch { }
    }
    return $set
}

function Get-BitLockerLetters {
    $set = @{}
    try {
        Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -ErrorAction Stop |
            Where-Object { $_.DriveLetter -and $_.ProtectionStatus -in 1, 2 } |
            ForEach-Object { $set[$_.DriveLetter.Substring(0, 1).ToUpper()] = $true }
    } catch { }
    return $set
}

function Get-Verdict($i) {
    $crit = @(); $warn = @()
    if ($i.PredictFailure -eq $true) { $crit += 'O SMART do disco prevê falha iminente' }
    if ($i.SmartPassed -eq $false)   { $crit += 'O autoteste de saúde SMART do disco FALHOU' }
    foreach ($a in $i.SmartFailedAttrs) { $crit += $a }
    if ($i.HealthStatus -eq 'Unhealthy') { $crit += 'O Windows marca o disco como Unhealthy' }
    elseif ($i.HealthStatus -eq 'Warning') { $warn += 'O Windows marca o disco com alerta (Warning)' }
    if ($i.OperationalStatus -and $i.OperationalStatus -notmatch '^(OK|Online)$') { $warn += "Status operacional: $($i.OperationalStatus)" }
    if ($i.ReadErrUnc -gt 0)  { $crit += "$($i.ReadErrUnc) erro(s) de leitura NÃO corrigido(s)" }
    if ($i.WriteErrUnc -gt 0) { $crit += "$($i.WriteErrUnc) erro(s) de escrita NÃO corrigido(s)" }

    # HDD / SSD SATA
    if ($i.Pending -gt 0) { $crit += "$($i.Pending) setor(es) pendente(s) (instáveis, aguardando realocação)" }
    if ($i.Uncorr -gt 0)  { $crit += "$($i.Uncorr) setor(es) incorrigível(is)" }
    if ($i.Realloc -gt 50) { $crit += "$($i.Realloc) setores realocados" }
    elseif ($i.Realloc -gt 0) { $warn += "$($i.Realloc) setor(es) realocado(s) - acompanhe se o número aumenta" }
    if ($i.ReportedUncorr -gt 0) { $warn += "$($i.ReportedUncorr) erro(s) incorrigível(is) reportado(s)" }
    if ($i.CRC -gt 0) { $warn += "$($i.CRC) erro(s) de CRC - geralmente cabo SATA ou conexão ruim, não o disco" }

    # NVMe
    if ($i.CriticalWarning -gt 0) { $crit += "Aviso crítico NVMe ativo (código $($i.CriticalWarning))" }
    if ($i.MediaErrors -gt 0) { $crit += "$($i.MediaErrors) erro(s) de mídia/integridade NVMe" }
    if ($null -ne $i.Spare -and $null -ne $i.SpareThresh -and $i.SpareThresh -gt 0 -and $i.Spare -le $i.SpareThresh) {
        $crit += "Reserva de blocos esgotada: $($i.Spare)% (limite $($i.SpareThresh)%)"
    }

    if ($i.Tipo -ne 'HDD' -and $null -ne $i.Wear) {
        if ($i.Wear -ge 90)     { $crit += "Vida útil consumida: $($i.Wear)%" }
        elseif ($i.Wear -ge 70) { $warn += "Vida útil consumida: $($i.Wear)%" }
    }
    if ($null -ne $i.TbwUsedPct) {
        if ($i.TbwUsedPct -ge 100) { $warn += "Já gravou $(Format-TB $i.TBW), acima dos $(Format-TB $i.RatedTBW) garantidos pelo fabricante (TBW)" }
        elseif ($i.TbwUsedPct -ge 90) { $warn += "Já usou $($i.TbwUsedPct)% do TBW garantido ($(Format-TB $i.TBW -NoUnit) de $(Format-TB $i.RatedTBW))" }
    }
    $tLimit = 55; if ($i.Tipo -ne 'HDD') { $tLimit = 70 }
    if ($i.Temp -ge $tLimit) { $warn += "Temperatura alta: $($i.Temp) °C (limite sugerido $tLimit °C)" }
    if ($i.Tipo -eq 'HDD' -and $i.PowerOnHours -gt 40000) { $warn += "Muitas horas ligado: $($i.PowerOnHours) h" }
    foreach ($h in $i.HistoryWarnings) { $warn += $h }

    $level = 'Bom'
    if ($warn.Count) { $level = 'Atenção' }
    if ($crit.Count) { $level = 'Crítico' }
    if (-not $crit.Count -and -not $warn.Count -and $null -eq $i.PredictFailure -and $null -eq $i.SmartPassed -and -not $i.HealthStatus) { $level = 'Sem dados' }
    if ($i.Size -le 0) {
        $level = 'Sem mídia'
        $crit = @('O disco informa capacidade de 0 bytes: leitor de cartão vazio, ou pendrive/disco com defeito ' +
                  '(controlador em modo de segurança). Testes e apagamento ficam bloqueados.') + $crit
    }
    return @{ Level = $level; Reasons = @($crit + $warn) }
}

function Get-DiskInventory([switch]$NoHistory) {
    $phys    = @(Get-PhysicalDisk -ErrorAction SilentlyContinue)
    $wmiDD   = @(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue)
    $predict = @()
    try { $predict = @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop) } catch { }
    $protected = Get-ProtectedDisks
    $bitlocker = Get-BitLockerLetters

    foreach ($d in @(Get-Disk | Sort-Object Number)) {
        $num = [int]$d.Number
        $p   = $phys | Where-Object { $_.DeviceId -eq "$num" } | Select-Object -First 1
        $rel = $null
        if ($p) { try { $rel = $p | Get-StorageReliabilityCounter -ErrorAction Stop } catch { } }

        $pf = $null
        $dd = $wmiDD | Where-Object { $_.Index -eq $num } | Select-Object -First 1
        if ($dd -and $dd.PNPDeviceID) {
            $m = $predict | Where-Object { $_.InstanceName.StartsWith($dd.PNPDeviceID, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
            if ($m) { $pf = [bool]$m.PredictFailure }
        }

        $bus   = [string]$d.BusType
        $media = ''; if ($p) { $media = [string]$p.MediaType }
        $tipo  = 'Desconhecido'
        if ($bus -eq 'NVMe') { $tipo = 'NVMe' }
        elseif ($media -eq 'SSD') { $tipo = 'SSD' }
        elseif ($media -eq 'HDD') { $tipo = 'HDD' }

        $parts = @(Get-Partition -DiskNumber $num -ErrorAction SilentlyContinue | Where-Object { "$($_.DriveLetter)" -match '[A-Z]' })
        $letters = @($parts | ForEach-Object { "$($_.DriveLetter):" })
        $blLetters = @($parts | Where-Object { $bitlocker.ContainsKey("$($_.DriveLetter)".ToUpper()) } | ForEach-Object { "$($_.DriveLetter):" })

        $health = ''; $opStatus = ''
        if ($p) { $health = [string]$p.HealthStatus; $opStatus = ($p.OperationalStatus -join ', ') }

        $info = [pscustomobject]@{
            Number = $num; Model = "$($d.FriendlyName)".Trim(); Serial = (Get-CleanSerial $d.SerialNumber)
            Firmware = "$($d.FirmwareVersion)".Trim(); Tipo = $tipo; Bus = $bus; Size = [int64]$d.Size
            PartitionStyle = [string]$d.PartitionStyle; PhysicalSector = [int]$d.PhysicalSectorSize
            HealthStatus = $health; OperationalStatus = $opStatus; PredictFailure = $pf
            Temp = $null; TempMax = $null; Wear = $null; PowerOnHours = $null
            ReadErrTotal = $null; ReadErrUnc = $null; WriteErrTotal = $null; WriteErrUnc = $null
            StartStop = $null; LoadUnload = $null
            SmartPassed = $null; SmartSource = 'Windows'; SmartDevArgs = $null; SmartFailedAttrs = @(); SmartError = $null
            Realloc = $null; Pending = $null; Uncorr = $null; CRC = $null; ReportedUncorr = $null
            MediaErrors = $null; Spare = $null; SpareThresh = $null; CriticalWarning = $null; UnsafeShutdowns = $null; TBW = $null
            TBR = $null; PowerCycles = $null; Rpm = $null; Standard = ''; LinkSpeed = ''; Features = ''; SmartJson = $null
            HealthPct = $null; RatedTBW = $null; RatedSource = $null; TbwUsedPct = $null; WriteRateTBDay = $null; RateSource = $null; RemainingYears = $null
            RemainingYearsTbw = $null; RemainingYearsWear = $null; RemainingBasis = $null; WearNote = $null
            Letters = ($letters -join ' '); BitLocker = ($blLetters -join ' ')
            Protected = $protected[$num]; HistoryWarnings = @(); PrevVerdict = $null; Verdict = ''; Reasons = @()
        }
        if ($rel) {
            if ($rel.Temperature -gt 0)    { $info.Temp = [int]$rel.Temperature }
            if ($rel.TemperatureMax -gt 0) { $info.TempMax = [int]$rel.TemperatureMax }
            if ($null -ne $rel.Wear -and $tipo -ne 'HDD') { $info.Wear = [int]$rel.Wear }
            $info.PowerOnHours = $rel.PowerOnHours
            $info.ReadErrTotal = $rel.ReadErrorsTotal;  $info.ReadErrUnc = $rel.ReadErrorsUncorrected
            $info.WriteErrTotal = $rel.WriteErrorsTotal; $info.WriteErrUnc = $rel.WriteErrorsUncorrected
            $info.StartStop = $rel.StartStopCycleCount; $info.LoadUnload = $rel.LoadUnloadCycleCount
            if ($rel.StartStopCycleCount -gt 0) { $info.PowerCycles = [int64]$rel.StartStopCycleCount }
        }
        if ($p -and $p.SpindleSpeed -gt 0 -and $p.SpindleSpeed -lt 100000) { $info.Rpm = [int]$p.SpindleSpeed }

        $sc = Get-SmartctlJson $num $tipo $info.Size
        if ($sc -and $sc.Json) { Merge-SmartctlData $info $sc.Json; $info.SmartDevArgs = $sc.DevArgs }
        elseif ($sc -and $sc.Error) { $info.SmartError = $sc.Error }
        # NVMe sem smartctl (ou bloqueado pelo Intel RST): lê o log de saúde direto pelo Windows
        if ($tipo -eq 'NVMe' -and $info.SmartSource -ne 'smartctl') {
            $nj = Get-NvmeHealthNative $num
            if ($nj) { Merge-SmartctlData $info $nj; $info.SmartSource = 'nvme'; $info.SmartError = $null }
        }

        if (-not $NoHistory) {
            $hist = @(Get-HealthHistory $info)
            $prev = $hist | Select-Object -Last 1
            if ($prev) {
                $info.PrevVerdict = [string]$prev.Diagnostico
                $when = ([datetime]$prev.Data).ToString('dd/MM/yyyy')
                foreach ($c in @(@('Realloc', 'Realocados', 'Setores realocados'), @('Pending', 'Pendentes', 'Setores pendentes'),
                                 @('Uncorr', 'Incorrigiveis', 'Setores incorrigíveis'), @('MediaErrors', 'ErrosMidia', 'Erros de mídia NVMe'))) {
                    if ($null -ne $info.($c[0]) -and $null -ne $prev.($c[1]) -and [double]$info.($c[0]) -gt [double]$prev.($c[1])) {
                        $info.HistoryWarnings += "$($c[2]) AUMENTARAM de $($prev.($c[1])) para $($info.($c[0])) desde $when"
                    }
                }
            }
        }

        if ($NoHistory) { $hist = @() }
        Update-Durability $info $hist
        $v = Get-Verdict $info
        $info.Verdict = $v.Level
        $info.Reasons = $v.Reasons
        if (-not $NoHistory) { Save-HealthSnapshot $info $hist }
        $info
    }
}

function Get-HealthReport($i, [switch]$WithSmartctl) {
    $L = New-Object System.Collections.Generic.List[string]
    $f = '{0,-37} {1}'
    $L.Add(('=' * 72))
    $L.Add("DISCO $($i.Number)  -  $($i.Model)")
    $L.Add(('=' * 72))
    $L.Add(($f -f 'Diagnóstico:', $i.Verdict.ToUpper()))
    foreach ($r in $i.Reasons) { $L.Add("   - $r") }
    $L.Add('')
    $L.Add(($f -f 'Tipo / Interface:', "$($i.Tipo) / $($i.Bus)"))
    $L.Add(($f -f 'Capacidade:', "$(Format-Size $i.Size)  ($($i.Size.ToString('N0')) bytes)"))
    $L.Add(($f -f 'Número de série:', (Show-Value $i.Serial)))
    $L.Add(($f -f 'Firmware:', (Show-Value $i.Firmware)))
    $L.Add(($f -f 'Tabela de partição:', $i.PartitionStyle))
    $L.Add(($f -f 'Unidades (letras):', (Show-Value $i.Letters)))
    if ($i.BitLocker) { $L.Add(($f -f 'BitLocker ativo em:', $i.BitLocker)) }
    if ($i.Protected) { $L.Add(($f -f 'PROTEGIDO:', $i.Protected)) }
    $L.Add('')
    $src = 'Windows (dados limitados)'; if ($i.SmartSource -eq 'smartctl') { $src = 'smartctl (SMART completo) + Windows' } elseif ($i.SmartSource -eq 'nvme') { $src = 'log de saúde NVMe (leitura direta pelo Windows)' }
    $L.Add(($f -f 'Fonte dos dados:', $src))
    if ($i.SmartError) {
        $L.Add(($f -f '', "O smartctl não tem acesso a este disco: $($i.SmartError)"))
        if ($RstController -and $i.Bus -in 'NVMe', 'RAID', 'SATA') {
            $L.Add(($f -f '', "Causa provável: o controlador '$($RstController.Name)' (Intel RST/VMD) não repassa"))
            $L.Add(($f -f '', 'comandos SMART de outros programas. Use o app da Intel/fabricante, ou desative o VMD'))
            $L.Add(($f -f '', 'na BIOS (exige cuidado: pode impedir o Windows de iniciar sem o driver certo).'))
        }
    }
    $pfText = 'n/d'
    if ($i.PredictFailure -eq $true) { $pfText = 'SIM - FALHA PREVISTA' } elseif ($i.PredictFailure -eq $false) { $pfText = 'Não (OK)' }
    $L.Add(($f -f 'SMART - previsão de falha (Windows):', $pfText))
    if ($null -ne $i.SmartPassed) {
        $st = 'APROVADO'; if (-not $i.SmartPassed) { $st = 'REPROVADO' }
        $L.Add(($f -f 'SMART - autoavaliação do disco:', $st))
    }
    $L.Add(($f -f 'Status de saúde (Windows):', (Show-Value $i.HealthStatus)))
    $L.Add(($f -f 'Status operacional:', (Show-Value $i.OperationalStatus)))
    $L.Add(($f -f 'Temperatura atual / máxima:', "$(Show-Value $i.Temp ' °C') / $(Show-Value $i.TempMax ' °C')"))
    if ($i.Tipo -ne 'HDD') { $L.Add(($f -f 'Vida útil consumida (desgaste):', (Show-Value $i.Wear '%'))) }
    $pohText = Show-Value $i.PowerOnHours ' h'
    if ($i.PowerOnHours) { $pohText += "  (~{0:N0} dias)" -f ($i.PowerOnHours / 24) }
    $L.Add(($f -f 'Horas ligado:', $pohText))
    if ($null -ne $i.TBR) { $L.Add(($f -f 'Total lido (pelo computador):', "$(Format-TB $i.TBR)")) }
    if ($null -ne $i.TBW) { $L.Add(($f -f 'Total gravado (pelo computador):', "$(Format-TB $i.TBW)")) }
    if ($null -ne $i.PowerCycles) { $L.Add(($f -f 'Contagem de ligações:', "$($i.PowerCycles) vezes")) }
    if ($i.Tipo -ne 'HDD' -and $i.Size -gt 0) {
        $L.Add('')
        $L.Add('--- Durabilidade (TBW) ---')
        $L.Add(($f -f 'Saúde (vida útil restante):', (Show-Value $i.HealthPct '%')))
        if ($i.RatedTBW) {
            $L.Add(($f -f 'TBW garantido:', "$(Format-TB $i.RatedTBW)  ($($i.RatedSource))"))
            if ($null -ne $i.TbwUsedPct) { $L.Add(($f -f 'TBW consumido:', "$('{0:N1}' -f $i.TbwUsedPct)%  ($(Format-TB $i.TBW -NoUnit) de $(Format-TB $i.RatedTBW))")) }
        } else {
            $L.Add(($f -f 'TBW garantido:', 'desconhecido - informe o da ficha do fabricante na janela Saúde detalhada'))
        }
        if ($i.WriteRateTBDay) { $L.Add(($f -f 'Ritmo de gravação:', ('{0:N1} GB/dia ({1})' -f ($i.WriteRateTBDay * 1000), $i.RateSource))) }
        if ($null -ne $i.RemainingYears) {
            $yrs = '{0:N1} anos' -f $i.RemainingYears; if ($i.RemainingYears -gt 50) { $yrs = 'mais de 50 anos' }
            $L.Add(($f -f 'Vida restante estimada:', "$yrs ($($i.RemainingBasis))"))
        }
        if ($i.WearNote) { $L.Add(($f -f 'Observação:', $i.WearNote))
        }
    }
    if ($i.Tipo -eq 'NVMe') {
        $L.Add(($f -f 'Reserva disponível / limite:', "$(Show-Value $i.Spare '%') / $(Show-Value $i.SpareThresh '%')"))
        $L.Add(($f -f 'Erros de mídia/integridade:', (Show-Value $i.MediaErrors)))
        $L.Add(($f -f 'Desligamentos inesperados:', (Show-Value $i.UnsafeShutdowns)))
        $L.Add(($f -f 'Aviso crítico:', (Show-Value $i.CriticalWarning)))
    } else {
        $L.Add(($f -f 'Setores realocados (5):', (Show-Value $i.Realloc)))
        $L.Add(($f -f 'Setores pendentes (197):', (Show-Value $i.Pending)))
        $L.Add(($f -f 'Setores incorrigíveis (198):', (Show-Value $i.Uncorr)))
        $L.Add(($f -f 'Erros de CRC / cabo (199):', (Show-Value $i.CRC)))
    }
    $L.Add(($f -f 'Erros de leitura (total/não corr.):', "$(Show-Value $i.ReadErrTotal) / $(Show-Value $i.ReadErrUnc)"))
    $L.Add(($f -f 'Erros de escrita (total/não corr.):', "$(Show-Value $i.WriteErrTotal) / $(Show-Value $i.WriteErrUnc)"))
    if ($i.Tipo -eq 'HDD') {
        $L.Add(($f -f 'Ciclos liga/desliga:', (Show-Value $i.StartStop)))
        $L.Add(($f -f 'Ciclos de carga do cabeçote:', (Show-Value $i.LoadUnload)))
    }
    $L.Add('')
    $L.Add('n/d = o disco ou o controlador (ex.: gavetas USB) não informa esse dado.')
    if (-not $SmartctlPath) {
        $L.Add('Para dados SMART completos, coloque o smartctl.exe (smartmontools) na pasta do DiskTool.')
    }

    if ($WithSmartctl -and $SmartctlPath) {
        $L.Add('')
        $L.Add('----- SMART completo (smartctl -x) -----')
        $dev = $i.SmartDevArgs; if (-not $dev) { $dev = @("/dev/pd$($i.Number)") }
        $L.Add((Invoke-Smartctl (@('-x') + $dev)).TrimEnd())
    }
    return ($L -join "`r`n")
}

# ---------------------------------------------------------------- Modo texto
if ($ListOnly) {
    if (-not (Test-Admin)) { Write-Warning 'Sem privilégios de administrador: alguns dados (temperatura, desgaste, erros) podem não aparecer.' }
    foreach ($i in @(Get-DiskInventory -NoHistory:(-not (Test-Admin)))) { Get-HealthReport $i; '' }
    exit
}

# ---------------------------------------------------------------- Monitor automático (tarefa agendada diária)
# Verifica os discos sem abrir janela, salva no histórico e mostra um aviso se algum piorou ou está crítico.
if ($Monitor) {
    $rank = @{ 'Bom' = 0; 'Sem dados' = 0; 'Atenção' = 1; 'Crítico' = 2 }
    $problems = @()
    foreach ($i in @(Get-DiskInventory)) {
        if ($i.Size -le 0) { continue }
        $worse = $i.PrevVerdict -and $rank.ContainsKey($i.PrevVerdict) -and $rank.ContainsKey($i.Verdict) -and $rank[$i.Verdict] -gt $rank[$i.PrevVerdict]
        if ($i.Verdict -eq 'Crítico' -or $worse -or $i.HistoryWarnings.Count) {
            $why = ''; if ($i.Reasons.Count) { $why = ": $($i.Reasons[0])" }
            $problems += "Disco $($i.Number) ($($i.Model)) - $($i.Verdict)$why"
        }
    }
    $msg = 'nenhum problema encontrado.'; if ($problems.Count) { $msg = $problems -join ' | ' }
    try { Add-Content -Path $LogFile -Value ('[{0:yyyy-MM-dd HH:mm:ss}] Monitor automático: {1}' -f (Get-Date), $msg) -Encoding UTF8 } catch { }
    if ($problems.Count) {
        Add-Type -AssemblyName System.Windows.Forms, System.Drawing
        $ni = New-Object Windows.Forms.NotifyIcon
        $ni.Icon = [Drawing.SystemIcons]::Warning
        if ($AppExe -and (Test-Path $AppExe)) { try { $ni.Icon = [Drawing.Icon]::ExtractAssociatedIcon($AppExe) } catch { } }
        $ni.Text = 'DiskTool'
        $ni.Visible = $true
        $text = ($problems -join "`n") + "`nAbra o DiskTool para ver os detalhes."
        if ($text.Length -gt 250) { $text = $text.Substring(0, 247) + '...' }
        $ni.ShowBalloonTip(20000, 'DiskTool - atenção com os discos', $text, [Windows.Forms.ToolTipIcon]::Warning)
        Start-Sleep -Seconds 25
        $ni.Dispose()
    }
    exit
}

$MonitorTaskName = 'DiskTool - Monitor de saude'
function Get-MonitorTask { Get-ScheduledTask -TaskName $MonitorTaskName -ErrorAction SilentlyContinue }

# Cria/atualiza ou remove a tarefa agendada do monitor (só quando o usuário salva nas Configurações).
function Set-MonitorTask([bool]$enable, [string]$time) {
    if (-not $enable) {
        if (Get-MonitorTask) { Unregister-ScheduledTask -TaskName $MonitorTaskName -Confirm:$false }
        return
    }
    if ($AppExe -and (Test-Path $AppExe)) { $exe = $AppExe; $arg = '-Monitor' }
    else { $exe = 'powershell.exe'; $arg = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" -Monitor" }
    $action    = New-ScheduledTaskAction -Execute $exe -Argument $arg
    $trigger   = New-ScheduledTaskTrigger -Daily -At ([datetime]::ParseExact($time, 'HH:mm', $null))
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
    Register-ScheduledTask -TaskName $MonitorTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description 'Verifica diariamente a saúde dos discos (DiskTool) e avisa se algum piorar.' -Force | Out-Null
}

# ---------------------------------------------------------------- Operações de preparo/formatação
function Clear-TargetDisk([int]$num) {
    $d = Get-Disk -Number $num
    if ($d.IsOffline)  { Set-Disk -Number $num -IsOffline $false }
    if ($d.IsReadOnly) { Set-Disk -Number $num -IsReadOnly $false }
    $d = Get-Disk -Number $num
    if ($d.PartitionStyle -ne 'RAW') {
        try { Clear-Disk -Number $num -RemoveData -RemoveOEM -Confirm:$false }
        catch {
            Write-Log "Disco $($num): Clear-Disk falhou ($($_.Exception.Message)); tentando via diskpart 'clean'..."
            Invoke-Diskpart @("select disk $num", 'attributes disk clear readonly noerr', 'online disk noerr', 'clean') | Out-Null
        }
    }
    Update-HostStorageCache -ErrorAction SilentlyContinue
}

function Initialize-AndFormat([int]$num, [string]$style, [string]$fs, [string]$label, [bool]$trim) {
    Update-HostStorageCache -ErrorAction SilentlyContinue
    $d = Get-Disk -Number $num
    if ($style -eq 'MBR' -and $d.Size -gt 2199023255552) {
        Write-Log "Disco $($num): maior que 2 TB, usando GPT em vez de MBR."
        $style = 'GPT'
    }
    if ($d.Size -le 0) { throw 'O disco informa capacidade de 0 bytes - não é possível formatar.' }
    if ($d.PartitionStyle -eq 'RAW') {
        try { Initialize-Disk -Number $num -PartitionStyle $style | Out-Null }
        catch {
            # Alguns pendrives já voltam inicializados depois da limpeza; só é erro se continuar RAW.
            Update-HostStorageCache -ErrorAction SilentlyContinue
            if ((Get-Disk -Number $num).PartitionStyle -eq 'RAW') { throw }
        }
    }

    $max = @{ NTFS = 32; exFAT = 15; FAT32 = 11 }[$fs]
    if ($label.Length -gt $max) { $label = $label.Substring(0, $max) }

    # Cria sem letra, formata e só então atribui a letra (evita o pop-up "formatar disco" do Explorer).
    $part = New-Partition -DiskNumber $num -UseMaximumSize
    Format-Volume -Partition $part -FileSystem $fs -NewFileSystemLabel $label -Confirm:$false -Force | Out-Null
    Add-PartitionAccessPath -DiskNumber $num -PartitionNumber $part.PartitionNumber -AssignDriveLetter
    $letter = "$((Get-Partition -DiskNumber $num -PartitionNumber $part.PartitionNumber).DriveLetter)"
    if ($trim -and $letter -match '[A-Z]') {
        try { Optimize-Volume -DriveLetter $letter -ReTrim; Write-Log "TRIM enviado para $($letter):" }
        catch { Write-Log "TRIM não suportado em $($letter): $($_.Exception.Message)" }
    }
    return $letter
}

# ---------------------------------------------------------------- Autoteste SMART (executado pelo próprio disco)
function Start-SelfTest($op) {
    $i = $op.Info
    if (-not $i.SmartDevArgs) { throw 'O smartctl não conseguiu acessar este disco (gavetas/adaptadores USB costumam bloquear).' }
    $type = 'short'; if ($op.Method -eq 'selftest_long') { $type = 'long' }
    $raw = Invoke-Smartctl (@('-j', '-t', $type) + $i.SmartDevArgs)
    $j = $null; try { $j = $raw | ConvertFrom-Json } catch { }
    $msgs = @(); if ($j -and $j.smartctl.messages) { $msgs = @($j.smartctl.messages | ForEach-Object { $_.string }) }
    $exit = 0; if ($j) { $exit = [int]$j.smartctl.exit_status }
    if (-not $j -or ($exit -band 7)) {
        $why = ($msgs -join ' '); if (-not $why) { $why = 'o disco ou o driver não aceitou o comando.' }
        throw "Autoteste não iniciado: $why"
    }
    $op.SelfTest = @{ Next = (Get-Date).AddSeconds(5); Started = Get-Date; SeenRunning = $false; Percent = 0; CancelReq = $false }
    Write-Log "Disco $($i.Number): autoteste SMART ($type) iniciado pelo disco."
}

# Retorna $true quando o autoteste terminou (resultado em $op.Results['selftest']).
function Update-SelfTest($op) {
    $st = $op.SelfTest
    $dev = $op.Info.SmartDevArgs
    if ($st.CancelReq) {
        [void](Invoke-Smartctl (@('-X') + $dev))
        $op.Results['selftest'] = @{ Passed = $null; Text = 'Cancelado pelo usuário'; Cancel = $true }
        $op.Cancelled = $true
        return $true
    }
    if ((Get-Date) -lt $st.Next) { return $false }
    $st.Next = (Get-Date).AddSeconds(10)
    $j = $null; try { $j = (Invoke-Smartctl (@('-j', '-c', '-l', 'selftest') + $dev)) | ConvertFrom-Json } catch { }
    if (-not $j) { return $false }

    $running = $false; $pct = $null; $result = $null
    $n = $j.nvme_self_test_log
    if ($n) {
        if ($n.current_self_test_operation -and [int]$n.current_self_test_operation.value -ne 0) {
            $running = $true; $pct = [int]$n.current_self_test_completion_percent
        } elseif ($n.table) {
            $t0 = @($n.table)[0]
            $result = @{ Passed = ([int]$t0.self_test_result.value -eq 0); Text = [string]$t0.self_test_result.string }
        }
    } elseif ($j.ata_smart_data -and $j.ata_smart_data.self_test) {
        $s = $j.ata_smart_data.self_test.status
        $v = [int]$s.value
        if (($v -shr 4) -eq 15) { $running = $true; $pct = 100 - [int]$s.remaining_percent }
        else { $result = @{ Passed = ($v -eq 0); Text = [string]$s.string } }
    }
    if ($running) { $st.SeenRunning = $true; $st.Percent = $pct; return $false }
    if (-not $st.SeenRunning -and ((Get-Date) - $st.Started).TotalSeconds -lt 40) { return $false }
    if (-not $result) { $result = @{ Passed = $null; Text = 'Não foi possível ler o resultado do autoteste.' } }
    $op.Results['selftest'] = $result
    return $true
}

# ---------------------------------------------------------------- Certificado de apagamento
# Só considera o apagamento concluído se a etapa que destrói os dados realmente terminou.
function Test-WipeComplete($op) {
    if ($op.Info.Size -le 0) { return $false }
    if (-not $op.Results['clear']) { return $false }
    switch ($op.Method) {
        'zero' {
            $z = $op.Results['zero']
            return [bool]($z -and -not $z.Error -and -not $z.Cancel -and $z.Total -gt 0 -and $z.Done -ge $z.Total -and $z.Total -eq $op.Info.Size)
        }
        'secure' { $e = $op.Results['erase']; return [bool]($e -and -not $e.Error) }
        default  { return $true }
    }
}

function New-WipeCertificate($op) {
    $i = $op.Info
    if (-not (Test-Path $CertDir)) { New-Item -ItemType Directory -Path $CertDir | Out-Null }
    $stamp = $op.StartTime.ToString('yyyyMMdd_HHmmss')
    $osTag = ''; if ($op.Opts.OS) { $osTag = 'OS' + (($op.Opts.OS -replace '[^\w\-]', '_')) + '_' }
    $base  = Join-Path $CertDir ("Certificado_{0}Disco{1}_{2}_{3}" -f $osTag, $i.Number, (Get-DiskKey $i), $stamp)

    $metodo = switch ($op.Method) {
        'quick'  { 'Limpeza lógica: remoção de partições + formatação rápida + TRIM' }
        'zero'   { 'Sobrescrita completa com zeros (1 passagem) em todos os setores endereçáveis' }
        'secure' { 'Apagamento pelo controlador do disco (IOCTL_STORAGE_REINITIALIZE_MEDIA)' }
    }
    $nivel = switch ($op.Method) {
        'quick'  { 'NÃO é apagamento seguro: em HDD os dados podem ser recuperáveis com software especializado.' }
        'zero'   { if ($i.Tipo -eq 'HDD') { 'Equivale ao nível "Clear" da norma NIST SP 800-88 para HDD.' }
                   else { 'Em SSD/NVMe a sobrescrita não alcança as áreas reservadas do controlador.' } }
        'secure' { 'Apagamento executado pelo firmware do disco, incluindo áreas não endereçáveis pelo sistema.' }
    }

    $z = $op.Results['zero']; $v = $op.Results['verify']; $e = $op.Results['erase']; $vs = $op.Results['verifysample']
    $verif = 'Não realizada'
    if ($v) {
        if ($v.Error) { $verif = "Interrompida: $($v.Error)" }
        elseif ($v.Cancel) { $verif = 'Cancelada' }
        elseif ($v.Mismatch -eq 0 -and $v.Errors -eq 0) { $verif = "APROVADA - leitura completa de $(Format-Size $v.Done): todos os bytes = 0x00" }
        else { $verif = "REPROVADA - $($v.Mismatch) bloco(s) de 1 MB com dados diferentes de zero, $($v.Errors) bloco(s) ilegível(is)" }
    } elseif ($vs) {
        if ($vs.Error) { $verif = "Interrompida: $($vs.Error)" }
        elseif ($vs.Mismatch -eq 0 -and $vs.Errors -eq 0) { $verif = ("APROVADA - {0} blocos amostrados ao longo do disco, todos com o padrão 0x{1:X2}" -f ($vs.Done / 1MB), $vs.Pattern) }
        else { $verif = "REPROVADA - $($vs.Mismatch) bloco(s) amostrado(s) com dados não uniformes, $($vs.Errors) ilegível(is)" }
    }

    if (-not (Test-WipeComplete $op)) { $op.Failed = $true }
    $status = 'CONCLUÍDO'
    if ($op.Failed) { $status = 'FALHOU / INCOMPLETO' }
    if ($op.Cancelled) { $status = 'CANCELADO' }
    if (-not $op.Failed -and ($v -or $vs)) { $status = 'CONCLUÍDO E VERIFICADO' }

    $dur = ((Get-Date) - $op.StartTime).TotalSeconds
    $rows = [ordered]@{
        'Identificador'         = $op.Id
        'Resultado'             = $status
        'Computador'            = $env:COMPUTERNAME
        'Operador (Windows)'    = "$env:USERDOMAIN\$env:USERNAME"
        'Início'                = $op.StartTime.ToString('dd/MM/yyyy HH:mm:ss')
        'Término'               = (Get-Date).ToString('dd/MM/yyyy HH:mm:ss')
        'Duração'               = Format-Duration $dur
        'Modelo do disco'       = $i.Model
        'Número de série'       = $i.Serial
        'Firmware'              = $i.Firmware
        'Tipo / Interface'      = "$($i.Tipo) / $($i.Bus)"
        'Capacidade'            = "$(Format-Size $i.Size) ($($i.Size.ToString('N0')) bytes)"
        'Saúde antes da operação' = $i.Verdict
        'Método'                = $metodo
        'Observação'            = $nivel
    }
    $pos = 2
    foreach ($pair in @(@('Empresa', $Settings.Empresa), @('Cliente', $op.Opts.Cliente), @('Nº da OS', $op.Opts.OS),
                        @('Técnico responsável', $Settings.Tecnico))) {
        if ($pair[1]) { $rows.Insert($pos, $pair[0], [string]$pair[1]); $pos++ }
    }
    if ($z) { $rows['Sobrescrita'] = "$(Format-Size $z.Done) de $(Format-Size $z.Total) gravados em $(Format-Duration $z.Seconds)" + $(if ($z.Error) { " - ERRO: $($z.Error)" } elseif ($z.Cancel) { ' - CANCELADA' } else { '' }) }
    if ($e) { $rows['Apagamento pelo controlador'] = $(if ($e.Error) { "ERRO: $($e.Error)" } else { "Aceito pelo disco em $(Format-Duration $e.Seconds)" }) }
    $rows['Verificação'] = $verif
    if ($op.Letter) { $rows['Formatação final'] = "$($op.Opts.Fs), unidade $($op.Letter):" }
    elseif ($op.FormatError) { $rows['Formatação final'] = "Erro: $($op.FormatError)" }
    $rows['Programa'] = "DiskTool $AppVersion"

    $txt = "CERTIFICADO DE APAGAMENTO DE DISCO`r`n" + ('=' * 60) + "`r`n"
    foreach ($k in $rows.Keys) { $txt += ('{0,-26} {1}' -f ($k + ':'), $rows[$k]) + "`r`n" }
    $sha = [Security.Cryptography.SHA256]::Create()
    $hash = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($txt)) | ForEach-Object { $_.ToString('x2') })
    $txt += "`r`nCódigo de integridade (SHA-256 do texto acima):`r`n$hash`r`n"
    [IO.File]::WriteAllText("$base.txt", $txt, (New-Object Text.UTF8Encoding($true)))

    $enc = { param($s) [Net.WebUtility]::HtmlEncode([string]$s) }
    $color = '#1e7a3c'; if ($op.Failed -or $op.Cancelled) { $color = '#b42318' }
    $trs = ($rows.Keys | ForEach-Object {
        $val = & $enc $rows[$_]
        if ($_ -eq 'Resultado') { $val = "<b style='color:$color'>$val</b>" }
        "<tr><th>$(& $enc $_)</th><td>$val</td></tr>"
    }) -join "`n"

    # Cabeçalho com logo e dados da empresa (Configurações)
    $logoHtml = ''
    if ($Settings.Logo -and (Test-Path $Settings.Logo)) {
        $ext = [IO.Path]::GetExtension($Settings.Logo).ToLower().TrimStart('.')
        $mime = @{ png = 'image/png'; jpg = 'image/jpeg'; jpeg = 'image/jpeg'; gif = 'image/gif'; bmp = 'image/bmp' }[$ext]
        if ($mime) { $logoHtml = "<img src='data:$mime;base64,$([Convert]::ToBase64String([IO.File]::ReadAllBytes($Settings.Logo)))' alt='logo'>" }
    }
    $compHtml = ''
    if ($Settings.Empresa) { $compHtml = "<div class='comp'><b>$(& $enc $Settings.Empresa)</b><br>$(& $enc $Settings.Contato)</div>" }
    $headHtml = ''
    if ($logoHtml -or $compHtml) { $headHtml = "<div class='head'>$logoHtml$compHtml</div>" }
    $signName = 'Responsável técnico'
    if ($Settings.Tecnico) { $signName = "Responsável técnico: $(& $enc $Settings.Tecnico)" }

    $html = @"
<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>Certificado de apagamento - $(& $enc $i.Serial)</title>
<style>
 body{font-family:'Segoe UI',Arial,sans-serif;color:#1a1a1a;margin:40px;}
 h1{font-size:22px;margin:0 0 4px} .sub{color:#555;margin-bottom:24px}
 table{border-collapse:collapse;width:100%;font-size:13px}
 th{text-align:left;width:230px;background:#f2f4f7;vertical-align:top}
 th,td{border:1px solid #d0d5dd;padding:7px 10px}
 .hash{font-family:Consolas,monospace;font-size:11px;word-break:break-all;color:#444;margin-top:18px}
 .sign{margin-top:60px;display:flex;gap:60px} .sign div{flex:1;border-top:1px solid #333;padding-top:6px;font-size:12px;text-align:center}
 .head{display:flex;align-items:center;gap:20px;border-bottom:2px solid #1a1a1a;padding-bottom:14px;margin-bottom:22px}
 .head img{max-height:64px;max-width:220px} .comp{font-size:13px;color:#333;line-height:1.5}
</style></head><body>
$headHtml
<h1>Certificado de apagamento de disco</h1>
<div class="sub">Gerado automaticamente pelo DiskTool $AppVersion em $((Get-Date).ToString('dd/MM/yyyy HH:mm'))</div>
<table>
$trs
</table>
<div class="hash">Código de integridade (SHA-256 do certificado em texto): $hash</div>
<div class="sign"><div>$signName</div><div>Data</div></div>
</body></html>
"@
    [IO.File]::WriteAllText("$base.html", $html, (New-Object Text.UTF8Encoding($true)))
    $op.CertPath = "$base.html"

    # Registro geral (CSV, abre no Excel) - uma linha por certificado
    try {
        $csv = Join-Path $CertDir 'Registro_de_apagamentos.csv'
        $q = { param($s) '"' + ([string]$s).Replace('"', '""') + '"' }
        if (-not (Test-Path $csv)) {
            [IO.File]::WriteAllText($csv, "Data;Cliente;OS;Técnico;Modelo;Serial;Capacidade;Tipo;Método;Resultado;Verificação;Identificador;SHA-256;Arquivo`r`n", (New-Object Text.UTF8Encoding($true)))
        }
        $line = (@((Get-Date).ToString('dd/MM/yyyy HH:mm'), $op.Opts.Cliente, $op.Opts.OS, $Settings.Tecnico, $i.Model, $i.Serial,
                   (Format-Size $i.Size), $i.Tipo, $MethodNames[$op.Method], $status, $verif, $op.Id, $hash,
                   [IO.Path]::GetFileName($base)) | ForEach-Object { & $q $_ }) -join ';'
        [IO.File]::AppendAllText($csv, $line + "`r`n", (New-Object Text.UTF8Encoding($false)))
    } catch { Write-Log "Não foi possível atualizar o registro CSV: $($_.Exception.Message)" }

    if (Convert-HtmlToPdf "$base.html" "$base.pdf") { $op.CertPath = "$base.pdf" }
    Write-Log "Disco $($i.Number): certificado salvo em $($op.CertPath)"
}

# PDF via Microsoft Edge em modo headless (se disponível). Retorna $true se o PDF foi criado.
function Convert-HtmlToPdf([string]$html, [string]$pdf) {
    $edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") |
            Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $edge) { return $false }
    # Aberto por um processo de administrador, o Edge se reinicia sem privilégios em outro processo e o
    # original termina antes do PDF existir; --do-not-de-elevate mantém tudo no mesmo processo.
    $work = Join-Path ([IO.Path]::GetTempPath()) ("disktool_pdf_" + [guid]::NewGuid().ToString('N'))
    $code = $null
    try {
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        Copy-Item -LiteralPath $html -Destination "$work\in.html"
        $pp = Start-Process -FilePath $edge -PassThru -WindowStyle Hidden -ArgumentList @(
            '--headless', '--disable-gpu', '--do-not-de-elevate', '--no-first-run', '--no-default-browser-check',
            '--disable-extensions', '--no-pdf-header-footer', "--user-data-dir=`"$work\profile`"",
            "--print-to-pdf=`"$work\out.pdf`"", "`"$(([Uri]"$work\in.html").AbsoluteUri)`"")
        if (-not $pp.WaitForExit(60000)) { try { $pp.Kill() } catch { } }
        $code = $pp.ExitCode
        for ($k = 0; $k -lt 60 -and -not (Test-Path "$work\out.pdf"); $k++) { Start-Sleep -Milliseconds 250 }
        if (Test-Path "$work\out.pdf") { Move-Item -LiteralPath "$work\out.pdf" -Destination $pdf -Force }
    } catch { $code = $_.Exception.Message }
    finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
    $ok = Test-Path -LiteralPath $pdf
    if (-not $ok -and (Get-Command Write-Log -ErrorAction SilentlyContinue)) { Write-Log "PDF não gerado pelo Edge (código: $code); mantido o HTML." }
    return $ok
}

# Cabeçalho (logo + empresa) usado no certificado e no laudo.
function Get-CompanyHeaderHtml {
    $enc = { param($s) [Net.WebUtility]::HtmlEncode([string]$s) }
    $logoHtml = ''
    if ($Settings.Logo -and (Test-Path $Settings.Logo)) {
        $ext = [IO.Path]::GetExtension($Settings.Logo).ToLower().TrimStart('.')
        $mime = @{ png = 'image/png'; jpg = 'image/jpeg'; jpeg = 'image/jpeg'; gif = 'image/gif'; bmp = 'image/bmp' }[$ext]
        if ($mime) { $logoHtml = "<img src='data:$mime;base64,$([Convert]::ToBase64String([IO.File]::ReadAllBytes($Settings.Logo)))' alt='logo'>" }
    }
    $compHtml = ''
    if ($Settings.Empresa) { $compHtml = "<div class='comp'><b>$(& $enc $Settings.Empresa)</b><br>$(& $enc $Settings.Contato)</div>" }
    if ($logoHtml -or $compHtml) { return "<div class='head'>$logoHtml$compHtml</div>" }
    return ''
}

# ---------------------------------------------------------------- Laudo técnico do disco (para o cliente)
# ---------------------------------------------------------------- Registro de laudos (planilha) e discos que já passaram por aqui
$LaudoCsv = Join-Path (Join-Path $ScriptDir 'Laudos') 'Registro_de_laudos.csv'

function Get-PreviousLaudos($i) {
    # Laudos anteriores do mesmo disco (pelo número de série). Serial vazio não identifica o disco: ignora.
    if (-not $i.Serial -or -not (Test-Path $LaudoCsv)) { return @() }
    try {
        return @(Import-Csv -Path $LaudoCsv -Delimiter ';' -Encoding UTF8 | Where-Object { $_.Serial -eq $i.Serial })
    } catch { return @() }
}

function Format-PreviousLaudos($prev, [int]$max = 3) {
    $prev = @($prev)
    $lines = @($prev | Select-Object -Last $max | ForEach-Object {
        $who = @(); if ($_.Cliente) { $who += "cliente $($_.Cliente)" }; if ($_.OS) { $who += "OS $($_.OS)" }
        "$($_.Data): $($_.Diagnóstico)" + $(if ($_.'Saúde %') { " ($($_.'Saúde %'))" } else { '' }) + $(if ($who.Count) { ' - ' + ($who -join ', ') } else { '' })
    })
    if ($prev.Count -gt $max) { $lines = @("(+$($prev.Count - $max) mais antigo(s))") + $lines }
    return $lines
}

function Add-LaudoRegistry($i, [string]$cliente, [string]$os, [string]$level, $entries, [string]$file) {
    try {
        $dir = Split-Path $LaudoCsv
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
        $q = { param($s) '"' + ([string]$s).Replace('"', '""') + '"' }
        if (-not (Test-Path $LaudoCsv)) {
            [IO.File]::WriteAllText($LaudoCsv, "Data;Cliente;OS;Técnico;Modelo;Serial;Capacidade;Tipo;Diagnóstico;Saúde %;Horas ligado;TB gravados;Testes;Arquivo`r`n", (New-Object Text.UTF8Encoding($true)))
        }
        $testes = (@($entries) | ForEach-Object { "$($_.Name): $($_.Text)" }) -join ' | '
        $line = (@((Get-Date).ToString('dd/MM/yyyy HH:mm'), $cliente, $os, $Settings.Tecnico, $i.Model, $i.Serial, (Format-Size $i.Size), $i.Tipo,
                   $level, $(if ($null -ne $i.HealthPct) { "$($i.HealthPct)%" } else { '' }), $i.PowerOnHours,
                   $(if ($null -ne $i.TBW) { '{0:N2}' -f [double]$i.TBW } else { '' }), $testes, $file) | ForEach-Object { & $q $_ }) -join ';'
        [IO.File]::AppendAllText($LaudoCsv, $line + "`r`n", (New-Object Text.UTF8Encoding($false)))
    } catch { Write-Log "Não foi possível atualizar o registro de laudos: $($_.Exception.Message)" }
}

function New-DiskLaudo($i, [string]$cliente, [string]$os, $tests) {
    $prevLaudos = @(Get-PreviousLaudos $i)   # lido antes de registrar este laudo
    $dir = Join-Path $ScriptDir 'Laudos'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    $osTag = ''; if ($os) { $osTag = 'OS' + ($os -replace '[^\w\-]', '_') + '_' }
    $base = Join-Path $dir ("Laudo_{0}Disco{1}_{2}_{3}" -f $osTag, $i.Number, (Get-DiskKey $i), (Get-Date).ToString('yyyyMMdd_HHmmss'))
    $enc = { param($s) [Net.WebUtility]::HtmlEncode([string]$s) }

    # Diagnóstico final: o pior entre o SMART e os testes feitos nesta sessão
    $level = $i.Verdict
    $reasons = @($i.Reasons)
    # Linhas da tabela de testes: o diagnóstico completo vira uma linha por etapa
    $entries = @(foreach ($t in $tests) {
        if ($t.SubResults) {
            foreach ($sr in $t.SubResults) { [pscustomobject]@{ Time = $t.StartTime; Name = "$($sr.Name) (diagnóstico completo)"; Text = $sr.Text; Smart = ($sr.Method -eq 'smart') } }
        } else { [pscustomobject]@{ Time = $t.StartTime; Name = $MethodNames[$t.Method]; Text = $t.ResultText; Smart = $false } }
    })
    foreach ($t in ($entries | Where-Object { -not $_.Smart })) {   # o SMART já entra pelo próprio veredito do disco
        if ($t.Text -match '^RUIM') { $level = 'Crítico'; $reasons += "$($t.Name): $($t.Text)" }
        elseif ($t.Text -match '^ATENÇÃO' -and $level -in 'Bom', 'Sem dados') { $level = 'Atenção'; $reasons += "$($t.Name): $($t.Text)" }
    }
    $rec = switch ($level) {
        'Bom'       { 'Disco em boas condições. Pode continuar em uso normalmente. Recomenda-se manter backup periódico dos dados.' }
        'Atenção'   { 'Disco funcional, mas com sinais de alerta. Recomenda-se backup frequente dos dados e nova verificação em até 30 dias.' }
        'Crítico'   { 'Risco elevado de falha e perda de dados. Recomenda-se backup imediato e a substituição do disco.' }
        'Sem mídia' { 'O dispositivo não apresenta capacidade utilizável (defeito no controlador ou na memória). Recomenda-se a substituição.' }
        default     { 'Não foi possível obter dados de saúde suficientes (comum em adaptadores USB). Recomenda-se repetir a análise com o disco ligado direto à placa-mãe.' }
    }
    $color = @{ 'Bom' = '#1e7a3c'; 'Atenção' = '#b26a00'; 'Crítico' = '#b42318' }[$level]; if (-not $color) { $color = '#555' }

    $rows = [ordered]@{
        'Modelo' = $i.Model; 'Número de série' = (Show-Value $i.Serial); 'Firmware' = (Show-Value $i.Firmware)
        'Tipo / Interface' = "$($i.Tipo) / $($i.Bus)"; 'Capacidade' = (Format-Size $i.Size)
        'Temperatura' = (Show-Value $i.Temp ' °C'); 'Horas ligado' = (Show-Value $i.PowerOnHours ' h')
    }
    if ($i.Tipo -ne 'HDD') { $rows['Saúde (vida útil restante)'] = (Show-Value $i.HealthPct '%') }
    if ($null -ne $i.TBR) { $rows['Total lido'] = "$(Format-TB $i.TBR)" }
    if ($null -ne $i.TBW) { $rows['Total gravado'] = "$(Format-TB $i.TBW)" }
    if ($i.Tipo -ne 'HDD' -and $i.RatedTBW) {
        $rows['TBW garantido pelo fabricante'] = "$(Format-TB $i.RatedTBW)"
        if ($null -ne $i.TbwUsedPct) { $rows['TBW consumido'] = ('{0:N1}%' -f $i.TbwUsedPct) }
        if ($null -ne $i.RemainingYears) {
            $rows['Vida restante estimada'] = $(if ($i.RemainingYears -gt 50) { 'mais de 50 anos' } else { '~{0:N1} anos ({1})' -f $i.RemainingYears, $i.RemainingBasis })
        }
        if ($i.WearNote) { $rows['Observação sobre o desgaste'] = $i.WearNote }
    }
    if ($i.Tipo -eq 'NVMe') {
        $rows['Erros de mídia'] = (Show-Value $i.MediaErrors); $rows['Reserva disponível'] = (Show-Value $i.Spare '%')
    } else {
        $rows['Setores realocados'] = (Show-Value $i.Realloc); $rows['Setores pendentes'] = (Show-Value $i.Pending)
        $rows['Setores incorrigíveis'] = (Show-Value $i.Uncorr)
    }
    $src = 'Windows (dados limitados)'; if ($i.SmartSource -eq 'smartctl') { $src = 'SMART completo (smartctl)' } elseif ($i.SmartSource -eq 'nvme') { $src = 'Log de saúde NVMe (leitura direta)' }
    $rows['Fonte dos dados'] = $src
    $trs = ($rows.Keys | ForEach-Object { "<tr><th>$(& $enc $_)</th><td>$(& $enc $rows[$_])</td></tr>" }) -join "`n"

    $testRows = ($entries | ForEach-Object {
        "<tr><td>$($_.Time.ToString('dd/MM/yyyy HH:mm'))</td><td>$(& $enc $_.Name)</td><td>$(& $enc $_.Text)</td></tr>"
    }) -join "`n"
    if (-not $testRows) { $testRows = "<tr><td colspan='3' class='muted'>Nenhum teste executado nesta sessão (diagnóstico baseado nos dados SMART).</td></tr>" }

    $histLines = @((Get-HistoryText $i) -split "`r`n" | Where-Object { $_ -match '->' -or $_ -match '^Variação|Estimativa' } | ForEach-Object { & $enc $_.Trim() })
    $histHtml = "<p class='muted'>Sem histórico anterior deste disco.</p>"
    if ($histLines.Count) { $histHtml = '<ul>' + (($histLines | ForEach-Object { "<li>$_</li>" }) -join '') + '</ul>' }
    $chart = Get-HistChartBase64 $i @(Get-HealthHistory $i)
    if ($chart) { $histHtml += "<img class='chart' src='data:image/png;base64,$chart' alt='Gráfico do histórico'>" }
    if ($prevLaudos.Count) {
        $histHtml += '<p><b>Diagnósticos anteriores deste disco nesta empresa:</b></p><ul>' +
                     ((Format-PreviousLaudos $prevLaudos 5 | ForEach-Object { "<li>$(& $enc $_)</li>" }) -join '') + '</ul>'
    }
    $reasonHtml = ''
    if ($reasons.Count) { $reasonHtml = '<ul>' + (($reasons | ForEach-Object { "<li>$(& $enc $_)</li>" }) -join '') + '</ul>' }

    $who = @()
    if ($cliente) { $who += "<b>Cliente:</b> $(& $enc $cliente)" }
    if ($os) { $who += "<b>Nº da OS:</b> $(& $enc $os)" }
    $who += "<b>Data:</b> $((Get-Date).ToString('dd/MM/yyyy HH:mm'))"
    $signName = 'Responsável técnico'; if ($Settings.Tecnico) { $signName = "Responsável técnico: $(& $enc $Settings.Tecnico)" }

    $html = @"
<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>Laudo técnico - $(& $enc $i.Model)</title>
<style>
 @page{margin:12mm} body{font-family:'Segoe UI',Arial,sans-serif;color:#1a1a1a;margin:0;font-size:12.5px}
 h1{font-size:21px;margin:0 0 4px} h2{font-size:14px;margin:18px 0 6px;border-bottom:1px solid #d0d5dd;padding-bottom:3px}
 .who{color:#333;margin-bottom:18px} .who span{margin-right:22px}
 .verdict{border:2px solid $color;border-radius:8px;padding:12px 16px;margin:14px 0}
 .verdict .lvl{font-size:20px;font-weight:700;color:$color} .verdict ul{margin:6px 0 0 18px;padding:0}
 table{border-collapse:collapse;width:100%} th{text-align:left;width:220px;background:#f2f4f7}
 th,td{border:1px solid #d0d5dd;padding:4px 9px;vertical-align:top} .tests th{width:auto} .tests td:first-child{white-space:nowrap}
 .muted{color:#666} ul{margin:4px 0 0 18px;padding:0}
 img.chart{width:100%;margin-top:8px;border:1px solid #d0d5dd;page-break-inside:avoid}
 .head{display:flex;align-items:center;gap:20px;border-bottom:2px solid #1a1a1a;padding-bottom:14px;margin-bottom:22px}
 .head img{max-height:64px;max-width:220px} .comp{font-size:13px;color:#333;line-height:1.5}
 .sign{margin-top:40px;display:flex;gap:60px;page-break-inside:avoid} .sign div{flex:1;border-top:1px solid #333;padding-top:6px;font-size:12px;text-align:center}
</style></head><body>
$(Get-CompanyHeaderHtml)
<h1>Laudo técnico de disco</h1>
<div class="who">$(($who | ForEach-Object { "<span>$_</span>" }) -join '')</div>
<div class="verdict"><div class="lvl">Diagnóstico: $(& $enc $level.ToUpper())</div>$reasonHtml
<p><b>Recomendação:</b> $(& $enc $rec)</p></div>
<h2>Identificação e dados de saúde</h2>
<table>
$trs
</table>
<h2>Testes realizados</h2>
<table class="tests"><tr><th>Data</th><th>Teste</th><th>Resultado</th></tr>
$testRows
</table>
<h2>Histórico</h2>
$histHtml
<div class="sign"><div>$signName</div><div>Assinatura do cliente</div></div>
<p class="muted" style="margin-top:24px">Gerado pelo DiskTool $AppVersion. Os dados de saúde refletem o estado do disco no momento da análise.</p>
</body></html>
"@
    [IO.File]::WriteAllText("$base.html", $html, (New-Object Text.UTF8Encoding($true)))
    $out = "$base.html"
    if (Convert-HtmlToPdf "$base.html" "$base.pdf") { $out = "$base.pdf" }
    Add-LaudoRegistry $i $cliente $os $level $entries ([IO.Path]::GetFileName($out))
    Write-Log "Disco $($i.Number): laudo técnico salvo em $out"
    return $out
}

# ---------------------------------------------------------------- Interface gráfica
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
if (-not ('DiskToolWin32.Native' -as [type])) {
    Add-Type -Name Native -Namespace DiskToolWin32 -MemberDefinition @"
[DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
[DllImport("dwmapi.dll")] public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
[DllImport("uxtheme.dll", CharSet = CharSet.Unicode)] public static extern int SetWindowTheme(IntPtr hwnd, string app, string idList);
"@
}
[void][DiskToolWin32.Native]::SetProcessDPIAware()
[Windows.Forms.Application]::EnableVisualStyles()

$g0 = [Drawing.Graphics]::FromHwnd([IntPtr]::Zero); $DpiScale = $g0.DpiX / 96.0; $g0.Dispose()
function S([double]$v) { [int]($v * $DpiScale) }

$fontUI   = New-Object Drawing.Font('Segoe UI', 9)
$fontMono = New-Object Drawing.Font('Consolas', 9)

# ---------------------------------------------------------------- Tema (claro / escuro)
function Test-WindowsDarkMode {
    try { return ((Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name AppsUseLightTheme -ErrorAction Stop).AppsUseLightTheme -eq 0) }
    catch { return $false }
}

function Get-ThemeIsDark {
    switch ($Settings.Theme) { 'Escuro' { return $true } 'Claro' { return $false } default { return (Test-WindowsDarkMode) } }
}

function Set-ThemePalette([bool]$dark) {
    $C = { param($r, $g, $b) [Drawing.Color]::FromArgb($r, $g, $b) }
    $script:IsDark = $dark
    if ($dark) {
        $script:Pal = @{
            Back = (& $C 32 32 32); Input = (& $C 22 22 22); Text = (& $C 232 232 232); Dim = (& $C 160 160 160)
            Button = (& $C 52 52 52); Border = (& $C 85 85 85); Header = (& $C 44 44 44)
            RowOk = (& $C 26 64 38); RowWarn = (& $C 90 72 16); RowBad = (& $C 104 34 34); RowNone = (& $C 56 56 56); RowNoneText = (& $C 165 165 165)
            ChartBack = (& $C 22 22 22); ChartText = (& $C 232 232 232); ChartDim = (& $C 160 160 160); ChartGrid = (& $C 58 58 58)
            ChartLine = (& $C 90 150 255); ChartAvg = (& $C 90 200 120); BarBack = (& $C 50 50 50); BarText = (& $C 240 240 240)
        }
    } else {
        $script:Pal = @{
            Back = [Drawing.SystemColors]::Control; Input = [Drawing.Color]::White; Text = [Drawing.SystemColors]::ControlText; Dim = [Drawing.Color]::DimGray
            Button = [Drawing.SystemColors]::Control; Border = [Drawing.Color]::Gray; Header = [Drawing.SystemColors]::Control
            RowOk = (& $C 215 245 215); RowWarn = (& $C 255 240 190); RowBad = (& $C 255 205 205); RowNone = (& $C 225 225 225); RowNoneText = [Drawing.Color]::DimGray
            ChartBack = [Drawing.Color]::White; ChartText = [Drawing.Color]::Black; ChartDim = [Drawing.Color]::DimGray; ChartGrid = (& $C 225 228 232)
            ChartLine = (& $C 37 99 235); ChartAvg = [Drawing.Color]::ForestGreen; BarBack = (& $C 232 234 237); BarText = [Drawing.Color]::Black
        }
    }
}

$script:ThemeHooked = @{}

function Set-ListViewTheme($lv, [bool]$dark) {
    try { [void][DiskToolWin32.Native]::SetWindowTheme($lv.Handle, $(if ($dark) { 'DarkMode_Explorer' } else { 'Explorer' }), $null) } catch { }
    $key = $lv.GetHashCode()
    if (-not $script:ThemeHooked.ContainsKey($key)) {
        $script:ThemeHooked[$key] = $true
        # Cabeçalho escuro desenhado à mão; itens continuam com o desenho padrão
        $lv.Add_DrawColumnHeader({
            param($s, $e)
            if (-not $script:IsDark) { $e.DrawDefault = $true; return }
            $b = $e.Bounds
            $e.Graphics.FillRectangle((New-Object Drawing.SolidBrush $script:Pal.Header), $b)
            $pen = New-Object Drawing.Pen $script:Pal.Border
            $e.Graphics.DrawLine($pen, ($b.Right - 1), $b.Top, ($b.Right - 1), $b.Bottom)
            $e.Graphics.DrawLine($pen, $b.Left, ($b.Bottom - 1), $b.Right, ($b.Bottom - 1))
            $r = New-Object Drawing.Rectangle(($b.X + 5), $b.Y, ($b.Width - 6), $b.Height)
            [Windows.Forms.TextRenderer]::DrawText($e.Graphics, $e.Header.Text, $s.Font, $r, $script:Pal.Text,
                [Windows.Forms.TextFormatFlags]'VerticalCenter, Left, EndEllipsis')
        })
        $lv.Add_DrawItem({ param($s, $e) $e.DrawDefault = $true })
        $lv.Add_DrawSubItem({ param($s, $e) $e.DrawDefault = $true })
    }
    $lv.OwnerDraw = $dark
    # Sem isso, a área do cabeçalho à direita da última coluna fica branca no tema escuro
    if ($dark -and $lv.Columns.Count) { $lv.Columns[$lv.Columns.Count - 1].Width = -2 }
    $lv.Invalidate()
}

function Set-TabTheme($tc, [bool]$dark) {
    $key = $tc.GetHashCode()
    if (-not $script:ThemeHooked.ContainsKey($key)) {
        $script:ThemeHooked[$key] = $true
        $tc.Add_DrawItem({
            param($s, $e)
            $sel = ($e.Index -eq $s.SelectedIndex)
            $bg = $script:Pal.Header; if ($sel) { $bg = $script:Pal.Back }
            $e.Graphics.FillRectangle((New-Object Drawing.SolidBrush $bg), $e.Bounds)
            [Windows.Forms.TextRenderer]::DrawText($e.Graphics, $s.TabPages[$e.Index].Text, $s.Font, $e.Bounds, $script:Pal.Text,
                [Windows.Forms.TextFormatFlags]'HorizontalCenter, VerticalCenter')
        })
    }
    $tc.DrawMode = $(if ($dark) { 'OwnerDrawFixed' } else { 'Normal' })
    $tc.Invalidate()
}

# Aplica o tema atual a uma janela e a todos os controles dela. Controles com Name = 'keep' mantêm as cores próprias.
function Set-Theme($root) {
    $p = $script:Pal; $dark = [bool]$script:IsDark
    $dimArgb = @([Drawing.Color]::DimGray.ToArgb(), [Drawing.Color]::Gray.ToArgb(), [Drawing.Color]::FromArgb(160, 160, 160).ToArgb())
    if ($root -is [Windows.Forms.Form]) {
        $root.BackColor = $p.Back; $root.ForeColor = $p.Text
        try {
            $v = [int]$dark
            [void][DiskToolWin32.Native]::DwmSetWindowAttribute($root.Handle, 20, [ref]$v, 4)
            [void][DiskToolWin32.Native]::DwmSetWindowAttribute($root.Handle, 19, [ref]$v, 4)
        } catch { }
    }
    $stack = New-Object System.Collections.Stack
    foreach ($c in $root.Controls) { $stack.Push($c) }
    while ($stack.Count) {
        $c = $stack.Pop()
        foreach ($ch in $c.Controls) { $stack.Push($ch) }
        if ($c.Name -eq 'keep') { continue }
        switch ($c.GetType().Name) {
            'Button' {
                if ($dark) { $c.FlatStyle = 'Flat'; $c.BackColor = $p.Button; $c.FlatAppearance.BorderColor = $p.Border }
                else { $c.FlatStyle = 'Standard'; $c.BackColor = [Drawing.SystemColors]::Control; $c.UseVisualStyleBackColor = $true }
                $c.ForeColor = $p.Text
            }
            'TextBox' {
                $c.BackColor = $p.Input; $c.ForeColor = $p.Text
                try { [void][DiskToolWin32.Native]::SetWindowTheme($c.Handle, $(if ($dark) { 'DarkMode_Explorer' } else { 'Explorer' }), $null) } catch { }
            }
            'ComboBox' { $c.BackColor = $p.Input; $c.ForeColor = $p.Text; $c.FlatStyle = $(if ($dark) { 'Flat' } else { 'Standard' }) }
            'DateTimePicker' { }
            'ListView' { $c.BackColor = $p.Input; $c.ForeColor = $p.Text; Set-ListViewTheme $c $dark }
            'PictureBox' { $c.BackColor = $p.ChartBack }
            'TabControl' { Set-TabTheme $c $dark }
            'TabPage' { $c.UseVisualStyleBackColor = (-not $dark); $c.BackColor = $p.Back; $c.ForeColor = $p.Text }
            default {
                # Label, CheckBox, RadioButton, GroupBox, painéis: herdam o fundo; textos cinza viram o cinza do tema
                if ($c.ForeColor.ToArgb() -in $dimArgb) { $c.ForeColor = $p.Dim }
                elseif ($c -is [Windows.Forms.GroupBox]) { $c.ForeColor = $p.Text }
            }
        }
    }
    $root.Refresh()
}

# Recolore as linhas da lista de operações conforme o resultado (usado ao trocar o tema)
function Update-OpRowColors {
    foreach ($op in @($script:Ops)) {
        if (-not $op.Item -or -not $op.RowKind) { continue }
        $op.Item.BackColor = @{ ok = $script:Pal.RowOk; warn = $script:Pal.RowWarn; bad = $script:Pal.RowBad }[$op.RowKind]
    }
}

Set-ThemePalette (Get-ThemeIsDark)

$form = New-Object Windows.Forms.Form
$form.SuspendLayout()
$form.AutoScaleDimensions = New-Object Drawing.SizeF(96, 96)
$form.AutoScaleMode = 'Dpi'
$form.Text = "DiskTool $AppVersion - Saúde e Formatação de Discos (NVMe / SSD / HDD)"
$form.ClientSize = New-Object Drawing.Size(1180, 860)
$form.MinimumSize = New-Object Drawing.Size(1000, 700)
$form.StartPosition = 'CenterScreen'
$form.Font = $fontUI
if ($AppExe -and (Test-Path $AppExe)) { try { $form.Icon = [Drawing.Icon]::ExtractAssociatedIcon($AppExe) } catch { } }

function New-Button($parent, $text, $x, $y, $w = 150, $h = 30) {
    $b = New-Object Windows.Forms.Button
    $b.Text = $text; $b.Location = New-Object Drawing.Point($x, $y); $b.Size = New-Object Drawing.Size($w, $h)
    $parent.Controls.Add($b); return $b
}
function New-Label($parent, $t, $x, $y) {
    $l = New-Object Windows.Forms.Label; $l.Text = $t; $l.AutoSize = $true; $l.Location = New-Object Drawing.Point($x, $y)
    $parent.Controls.Add($l); return $l
}

# Lista de discos
$lv = New-Object Windows.Forms.ListView
$lv.View = 'Details'; $lv.FullRowSelect = $true; $lv.MultiSelect = $true; $lv.HideSelection = $false; $lv.GridLines = $true
$lv.Location = New-Object Drawing.Point(10, 10); $lv.Size = New-Object Drawing.Size(1160, 200)
$lv.Anchor = 'Top, Left, Right'
foreach ($c in @(@('Disco', 45), @('Modelo', 200), @('Tipo', 50), @('Interface', 62), @('Capacidade', 75), @('Saúde', 92),
                 @('Temp.', 50), @('Desgaste', 62), @('Horas ligado', 78), @('Realoc./Pend.', 85), @('Gravado / TBW', 95),
                 @('Letras', 60), @('BitLocker', 65), @('Protegido', 200))) {
    [void]$lv.Columns.Add($c[0], (S $c[1]))
}
$form.Controls.Add($lv)

$btnRefresh = New-Button $form 'Atualizar lista' 10 218 95
$btnDiag    = New-Button $form '✔ Diagnóstico completo' 110 218 160
$btnDiag.Font = New-Object Drawing.Font($btnDiag.Font, [Drawing.FontStyle]::Bold)
$btnSmart   = New-Button $form 'Saúde detalhada' 275 218 115
$btnFull    = New-Button $form 'Teste de leitura completo' 395 218 155
$btnSample  = New-Button $form 'Teste rápido (amostragem)' 555 218 160
$btnSelf    = New-Button $form 'Mais testes ▾' 720 218 100
$btnExport  = New-Button $form 'Relatórios ▾' 825 218 100
$cmsRep = New-Object Windows.Forms.ContextMenuStrip
$miLaudo  = $cmsRep.Items.Add('Laudo técnico do disco selecionado (PDF, para o cliente)')
$miExport = $cmsRep.Items.Add('Relatório completo de todos os discos (TXT)')
[void]$cmsRep.Items.Add((New-Object Windows.Forms.ToolStripSeparator))
$miLaudos = $cmsRep.Items.Add('Abrir pasta de laudos')
$miLaudoCsv = $cmsRep.Items.Add('Abrir registro de laudos (planilha - todos os discos já diagnosticados)')
$btnConfig  = New-Button $form 'Configurações' 930 218 100
$lblSmart = New-Label $form '' 1040 225
$lblSmart.Anchor = 'Top, Left'
$cmsSelf = New-Object Windows.Forms.ContextMenuStrip
$miShort = $cmsSelf.Items.Add('Autoteste SMART curto  (cerca de 2 minutos)')
$miLong  = $cmsSelf.Items.Add('Autoteste SMART longo  (varre o disco inteiro - pode levar horas em HDD)')
[void]$cmsSelf.Items.Add((New-Object Windows.Forms.ToolStripSeparator))
$miBench = $cmsSelf.Items.Add('Benchmark de velocidade  (arquivo temporário de 1 GB - não apaga dados)')
[void]$cmsSelf.Items.Add((New-Object Windows.Forms.ToolStripSeparator))
$miFake  = $cmsSelf.Items.Add('Teste de capacidade real - pendrive/cartão falsificado  (APAGA o disco)')

# Grupo de formatação
$grp = New-Object Windows.Forms.GroupBox
$grp.Text = 'Formatar / Zerar discos selecionados  (APAGA TODOS OS DADOS)'
$grp.Location = New-Object Drawing.Point(10, 256); $grp.Size = New-Object Drawing.Size(1160, 132)
$grp.Anchor = 'Top, Left, Right'
$form.Controls.Add($grp)

$rbQuick = New-Object Windows.Forms.RadioButton
$rbQuick.Text = 'Rápido: apaga partições + formata + TRIM  (uso normal em SSD / NVMe)'
$rbQuick.Location = New-Object Drawing.Point(15, 20); $rbQuick.AutoSize = $true; $rbQuick.Checked = $true
$rbZero = New-Object Windows.Forms.RadioButton
$rbZero.Text = 'Completo: sobrescreve TODO o disco com zeros  (recomendado para HDD)'
$rbZero.Location = New-Object Drawing.Point(15, 43); $rbZero.AutoSize = $true
$rbSecure = New-Object Windows.Forms.RadioButton
$rbSecure.Text = 'Apagamento seguro pelo controlador  (NVMe / SSD - experimental, depende do disco/driver)'
$rbSecure.Location = New-Object Drawing.Point(15, 66); $rbSecure.AutoSize = $true
$grp.Controls.AddRange(@($rbQuick, $rbZero, $rbSecure))

$chkVerify = New-Object Windows.Forms.CheckBox
$chkVerify.Text = 'Verificar após apagar'; $chkVerify.Checked = $true; $chkVerify.AutoSize = $true
$chkVerify.Location = New-Object Drawing.Point(620, 43)
$chkCert = New-Object Windows.Forms.CheckBox
$chkCert.Text = 'Gerar certificado'; $chkCert.Checked = $true; $chkCert.AutoSize = $true
$chkCert.Location = New-Object Drawing.Point(620, 66)
$grp.Controls.AddRange(@($chkVerify, $chkCert))
[void](New-Label $grp 'Cliente:' 790 22)
$tbCliente = New-Object Windows.Forms.TextBox
$tbCliente.Location = New-Object Drawing.Point(845, 19); $tbCliente.Width = 125
[void](New-Label $grp 'Nº OS:' 790 49)
$tbOS = New-Object Windows.Forms.TextBox
$tbOS.Location = New-Object Drawing.Point(845, 46); $tbOS.Width = 125
$grp.Controls.AddRange(@($tbCliente, $tbOS))
$chkThermal = New-Object Windows.Forms.CheckBox
$chkThermal.Text = 'Pausar se esquentar'; $chkThermal.Checked = $true; $chkThermal.AutoSize = $true
$chkThermal.Location = New-Object Drawing.Point(790, 99)
$grp.Controls.Add($chkThermal)
$tipThermal = New-Object Windows.Forms.ToolTip
$tipThermal.SetToolTip($chkThermal, 'Pausa testes, zeragem e benchmark se o disco passar de 55 °C (HDD), 70 °C (SSD) ou 78 °C (NVMe) e retoma ao esfriar.')

[void](New-Label $grp 'Tabela:' 15 100)
$cbStyle = New-Object Windows.Forms.ComboBox
$cbStyle.DropDownStyle = 'DropDownList'; [void]$cbStyle.Items.AddRange(@('GPT', 'MBR')); $cbStyle.SelectedIndex = 0
$cbStyle.Location = New-Object Drawing.Point(65, 97); $cbStyle.Width = 70
[void](New-Label $grp 'Sistema de arquivos:' 150 100)
$cbFs = New-Object Windows.Forms.ComboBox
$cbFs.DropDownStyle = 'DropDownList'; [void]$cbFs.Items.AddRange(@('NTFS', 'exFAT', 'FAT32')); $cbFs.SelectedIndex = 0
$cbFs.Location = New-Object Drawing.Point(275, 97); $cbFs.Width = 80
[void](New-Label $grp 'Rótulo:' 370 100)
$tbLabel = New-Object Windows.Forms.TextBox
$tbLabel.Text = 'Disco'; $tbLabel.Location = New-Object Drawing.Point(420, 97); $tbLabel.Width = 150
$chkFormat = New-Object Windows.Forms.CheckBox
$chkFormat.Text = 'Formatar ao final'; $chkFormat.Checked = $true; $chkFormat.AutoSize = $true
$chkFormat.Location = New-Object Drawing.Point(620, 99)
$grp.Controls.AddRange(@($cbStyle, $cbFs, $tbLabel, $chkFormat))

$btnWipe = New-Object Windows.Forms.Button
$btnWipe.Text = 'EXECUTAR'; $btnWipe.Size = New-Object Drawing.Size(160, 56)
$btnWipe.Location = New-Object Drawing.Point(985, 40); $btnWipe.Anchor = 'Top, Right'
$btnWipe.BackColor = [Drawing.Color]::FromArgb(200, 40, 40); $btnWipe.ForeColor = 'White'
$btnWipe.FlatStyle = 'Flat'; $btnWipe.Font = New-Object Drawing.Font('Segoe UI', 10, [Drawing.FontStyle]::Bold)
$btnWipe.Name = 'keep'
$grp.Controls.Add($btnWipe)

# Lista de operações (várias em paralelo)
[void](New-Label $form 'Operações em andamento / concluídas:' 10 396)
$chkBench = New-Object Windows.Forms.CheckBox
$chkBench.Text = 'Modo bancada: diagnosticar automaticamente cada disco que for conectado'
$chkBench.AutoSize = $true; $chkBench.Location = New-Object Drawing.Point(260, 394); $chkBench.Checked = [bool]$Settings.Bancada
$form.Controls.Add($chkBench)
$tipBench = New-Object Windows.Forms.ToolTip
$tipBench.SetToolTip($chkBench, ("Ao conectar um disco (USB, dock, SATA hot-swap), o DiskTool roda o Diagnóstico completo sozinho e salva o laudo em PDF.`r`n" +
    "Só lê o disco - nada é apagado. Discos do sistema e os que já estavam conectados não são testados. Cliente/OS preenchidos vão para o laudo."))
$lvOps = New-Object Windows.Forms.ListView
$lvOps.View = 'Details'; $lvOps.FullRowSelect = $true; $lvOps.MultiSelect = $false; $lvOps.HideSelection = $false; $lvOps.GridLines = $true
$lvOps.Location = New-Object Drawing.Point(10, 414); $lvOps.Size = New-Object Drawing.Size(1010, 126)
$lvOps.Anchor = 'Top, Left, Right'
foreach ($c in @(@('Disco', 45), @('Modelo', 180), @('Operação', 130), @('Etapa', 140), @('Progresso', 70),
                 @('Velocidade', 80), @('Restante', 70), @('Resultado', 270))) {
    [void]$lvOps.Columns.Add($c[0], (S $c[1]))
}
$form.Controls.Add($lvOps)
$btnCancel = New-Button $form 'Cancelar selecionada' 1030 414 140 28
$btnCancel.Anchor = 'Top, Right'
$btnRepair = New-Button $form 'Reparar setores (HDD)' 1030 446 140 28
$btnRepair.Anchor = 'Top, Right'
$btnCerts = New-Button $form 'Abrir certificados' 1030 478 140 28
$btnCerts.Anchor = 'Top, Right'
$btnClearOps = New-Button $form 'Limpar concluídas' 1030 510 140 28
$btnClearOps.Anchor = 'Top, Right'

$progress = New-Object Windows.Forms.ProgressBar
$progress.Location = New-Object Drawing.Point(10, 546); $progress.Size = New-Object Drawing.Size(1160, 14)
$progress.Anchor = 'Top, Left, Right'; $progress.Maximum = 1000
$form.Controls.Add($progress)
$lblStatus = New-Label $form 'Pronto.' 10 564
$lblStatus.AutoSize = $false; $lblStatus.Size = New-Object Drawing.Size(1160, 18); $lblStatus.Anchor = 'Top, Left, Right'

# Abas
$tabs = New-Object Windows.Forms.TabControl
$tabs.Location = New-Object Drawing.Point(10, 586); $tabs.Size = New-Object Drawing.Size(1160, 264)
$tabs.Anchor = 'Top, Bottom, Left, Right'
function New-TextTab($title) {
    $t = New-Object Windows.Forms.TabPage($title)
    $tb = New-Object Windows.Forms.TextBox
    $tb.Multiline = $true; $tb.ReadOnly = $true; $tb.ScrollBars = 'Both'; $tb.WordWrap = $false
    $tb.Dock = 'Fill'; $tb.Font = $fontMono; $tb.BackColor = 'White'
    $t.Controls.Add($tb)
    return $t
}
$tabDet  = New-TextTab 'Detalhes de saúde'
$tabHist = New-TextTab 'Histórico'
$tabLog  = New-TextTab 'Log'
$tabChart = New-Object Windows.Forms.TabPage('Gráfico de velocidade')
$pic = New-Object Windows.Forms.PictureBox
$pic.Dock = 'Fill'; $pic.BackColor = 'White'
$tabChart.Controls.Add($pic)
$tabHistChart = New-Object Windows.Forms.TabPage('Gráfico do histórico')
$picHist = New-Object Windows.Forms.PictureBox
$picHist.Dock = 'Fill'; $picHist.BackColor = 'White'
$tabHistChart.Controls.Add($picHist)
$script:HistDisk = $null; $script:HistData = @()
$txtDet = $tabDet.Controls[0]; $txtHist = $tabHist.Controls[0]; $txtLog = $tabLog.Controls[0]
$tabs.TabPages.AddRange(@($tabDet, $tabHist, $tabHistChart, $tabChart, $tabLog))
$form.Controls.Add($tabs)

$timer = New-Object Windows.Forms.Timer
$timer.Interval = 500

$script:Ops = New-Object System.Collections.ArrayList
$script:Batch = New-Object System.Collections.ArrayList
$script:ChartOp = $null
$script:Disks = @()

$StageNames = @{
    clear = 'Removendo partições'; zero = 'Zerando'; verify = 'Verificando zeros'; erase = 'Apagando (controlador)'
    verifysample = 'Verificando (amostragem)'; format = 'Formatando'; cert = 'Gerando certificado'
    read = 'Lendo o disco inteiro'; sample = 'Lendo amostras'; repair = 'Reparando setores'; selftest = 'Autoteste no disco'; bench = 'Benchmark'; fakecheck = 'Testando capacidade'
}
$MethodNames = @{
    quick = 'Formatação rápida'; zero = 'Zeragem completa'; secure = 'Apagamento seguro'
    read = 'Teste completo'; sample = 'Teste rápido'; repair = 'Reparo de setores'
    selftest_short = 'Autoteste SMART curto'; selftest_long = 'Autoteste SMART longo'; bench = 'Benchmark'; fakecheck = 'Teste de capacidade real'
    diag = 'Diagnóstico completo'
}

# ---------------------------------------------------------------- Lógica da GUI
function Write-Log([string]$msg) {
    $txtLog.AppendText(('[{0:HH:mm:ss}] {1}' -f (Get-Date), $msg) + "`r`n")
    try { Add-Content -Path $LogFile -Value ('[{0:yyyy-MM-dd HH:mm:ss}] {1}' -f (Get-Date), $msg) -Encoding UTF8 } catch { }
}

function Show-Msg($text, $icon = 'Information', $buttons = 'OK') {
    [Windows.Forms.MessageBox]::Show($form, $text, 'DiskTool', $buttons, $icon)
}

function Get-ActiveOps { @($script:Ops | Where-Object { $_.Active }) }

function Test-DiskBusy([int]$num) { [bool](Get-ActiveOps | Where-Object { $_.Info.Number -eq $num }) }

# Assinatura barata do conjunto de discos (número, serial, tamanho, estado) - sem ler SMART.
function Get-DiskSetSignature {
    try {
        return ((@(Get-Disk -ErrorAction Stop | Sort-Object Number | ForEach-Object {
            "$($_.Number)|$(Get-CleanSerial $_.SerialNumber)|$($_.Size)|$($_.OperationalStatus)|$($_.IsOffline)"
        })) -join ';')
    } catch { return $null }
}

function Update-DiskList {
    if ($script:InDiskList) { return }   # evita releitura aninhada (DoEvents durante a leitura)
    $script:InDiskList = $true
    try { Update-DiskListCore } finally { $script:InDiskList = $false }
}

function Update-DiskListCore {
    $script:DiskSetSig = Get-DiskSetSignature
    $form.Cursor = 'WaitCursor'
    $lblStatus.Text = 'Lendo discos e dados SMART...'
    [Windows.Forms.Application]::DoEvents()
    $selected = @($lv.SelectedItems | ForEach-Object { $_.Tag.Number })
    $lv.BeginUpdate(); $lv.Items.Clear()
    try {
        $script:Disks = @(Get-DiskInventory)
        foreach ($i in $script:Disks) {
            $it = New-Object Windows.Forms.ListViewItem([string]$i.Number)
            $wearText = ''; if ($null -ne $i.Wear) { $wearText = "$($i.Wear)%" }
            $rp = ''
            if ($i.Tipo -eq 'NVMe') { if ($null -ne $i.MediaErrors) { $rp = "mídia: $($i.MediaErrors)" } }
            elseif ($null -ne $i.Realloc -or $null -ne $i.Pending) { $rp = "$(Show-Value $i.Realloc) / $(Show-Value $i.Pending)" }
            $tbw = ''; if ($null -ne $i.TBW) { $tbw = "$(Format-TB $i.TBW)"; if ($i.RatedTBW) { $tbw = "$(Format-TB $i.TBW -NoUnit) / $(Format-TB $i.RatedTBW)" } }
            foreach ($v in @($i.Model, $i.Tipo, $i.Bus, (Format-Size $i.Size), (Format-HealthLabel $i), (Show-Value $i.Temp ' °C'), $wearText,
                             (Show-Value $i.PowerOnHours), $rp, $tbw, $i.Letters, $i.BitLocker, $i.Protected)) {
                [void]$it.SubItems.Add([string]$v)
            }
            switch ($i.Verdict) {
                'Crítico' { $it.BackColor = $script:Pal.RowBad }
                'Atenção' { $it.BackColor = $script:Pal.RowWarn }
                'Bom'     { $it.BackColor = $script:Pal.RowOk }
                'Sem mídia' { $it.BackColor = $script:Pal.RowNone; $it.ForeColor = $script:Pal.RowNoneText }
            }
            $it.Tag = $i
            [void]$lv.Items.Add($it)
            if ($selected -contains $i.Number) { $it.Selected = $true }
        }
        Write-Log "$($script:Disks.Count) disco(s) encontrado(s)."
    } catch {
        Write-Log "Erro ao listar discos: $($_.Exception.Message)"
    } finally {
        $lv.EndUpdate(); $form.Cursor = 'Default'; $lblStatus.Text = 'Pronto.'
    }
    if ($lv.Items.Count -and $lv.SelectedItems.Count -eq 0) { $lv.Items[0].Selected = $true }
}

function Get-SelectedDisks {
    $sel = @($lv.SelectedItems | ForEach-Object { $_.Tag })
    if (-not $sel.Count) { Show-Msg 'Selecione um ou mais discos na lista (Ctrl+clique para vários).' 'Warning' | Out-Null }
    return $sel
}

function Test-SameDisk($info) {
    # Garante que o número do disco ainda aponta para o mesmo disco físico (ex.: pendrive/USB trocado).
    try { $d = Get-Disk -Number $info.Number } catch { return $false }
    return ((Get-CleanSerial $d.SerialNumber) -eq $info.Serial -and [int64]$d.Size -eq $info.Size -and $info.Size -gt 0)
}

function Show-ConfirmWipe($disks, [string]$modeText, [string]$prefix = 'APAGAR',
                          [string]$headline = 'TODOS OS DADOS dos discos abaixo serão destruídos permanentemente.', [string]$okText = 'Apagar') {
    $expected = "$prefix " + (($disks | ForEach-Object { $_.Number }) -join ',')
    $f = New-Object Windows.Forms.Form
    $f.SuspendLayout()
    $f.AutoScaleDimensions = New-Object Drawing.SizeF(96, 96); $f.AutoScaleMode = 'Dpi'
    $f.Text = 'Confirmação - operação irreversível'; $f.ClientSize = New-Object Drawing.Size(560, 400)
    $f.FormBorderStyle = 'FixedDialog'; $f.StartPosition = 'CenterParent'; $f.MaximizeBox = $false; $f.MinimizeBox = $false
    $f.Font = $fontUI
    $txt = "$headline`r`nModo: $modeText`r`n`r`n"
    foreach ($i in $disks) {
        $txt += "Disco $($i.Number):  $($i.Model)  -  $(Format-Size $i.Size)  ($($i.Tipo))`r`n"
        $txt += "     Serial: $($i.Serial)   Unidades: $(Show-Value $i.Letters)`r`n"
        if ($i.BitLocker) { $txt += "     ATENÇÃO: BitLocker ativo em $($i.BitLocker) - verifique se é mesmo este disco!`r`n" }
    }
    $txt += "`r`nPara confirmar, digite exatamente:   $expected"
    $tbInfo = New-Object Windows.Forms.TextBox
    $tbInfo.Multiline = $true; $tbInfo.ReadOnly = $true; $tbInfo.ScrollBars = 'Vertical'; $tbInfo.Text = $txt
    $tbInfo.Location = New-Object Drawing.Point(15, 12); $tbInfo.Size = New-Object Drawing.Size(530, 290)
    $tb = New-Object Windows.Forms.TextBox
    $tb.Location = New-Object Drawing.Point(15, 314); $tb.Width = 530
    $ok = New-Object Windows.Forms.Button
    $ok.Text = $okText; $ok.Enabled = $false; $ok.DialogResult = 'OK'
    $ok.Location = New-Object Drawing.Point(320, 352); $ok.Size = New-Object Drawing.Size(110, 32)
    $cancel = New-Object Windows.Forms.Button
    $cancel.Text = 'Cancelar'; $cancel.DialogResult = 'Cancel'
    $cancel.Location = New-Object Drawing.Point(435, 352); $cancel.Size = New-Object Drawing.Size(110, 32)
    $tb.Add_TextChanged({ $ok.Enabled = (($tb.Text.Trim().ToUpper() -replace '\s*,\s*', ',') -eq $expected) }.GetNewClosure())
    $f.Controls.AddRange(@($tbInfo, $tb, $ok, $cancel))
    $f.CancelButton = $cancel
    $f.ResumeLayout($false)
    $f.Add_Shown({ $tb.Focus() }.GetNewClosure())
    $f.Add_Load({ param($s, $e) Set-Theme $s })
    return ($f.ShowDialog($form) -eq 'OK')
}

# ----- Motor de operações: cada operação é uma fila de etapas; etapas longas rodam em DiskJob (thread)
function New-Op($info, [string]$kind, [string]$method, [string[]]$stages, $opts) {
    $q = New-Object 'System.Collections.Generic.Queue[string]'
    foreach ($s in $stages) { $q.Enqueue($s) }
    $op = [pscustomobject]@{
        Id = [guid]::NewGuid().ToString().ToUpper(); Kind = $kind; Method = $method; Info = $info; Opts = $opts
        Queue = $q; Stage = ''; Job = $null; Active = $true; Failed = $false; Cancelled = $false
        StartTime = Get-Date; Results = @{}; Curve = $null; CurveTitle = ''; Letter = $null; FormatError = $null
        CertPath = $null; Summary = ''; Item = $null; SelfTest = $null; SubResults = $null; LaudoPath = $null
        ResultText = ''; RowKind = $null; Busy = $false; Closed = $false; NextTempCheck = (Get-Date).AddSeconds(20); TempPaused = $false; LastTemp = $null
    }
    $it = New-Object Windows.Forms.ListViewItem([string]$info.Number)
    foreach ($v in @($info.Model, $MethodNames[$method], '', '', '', '', '')) { [void]$it.SubItems.Add($v) }
    $it.Tag = $op
    $op.Item = $it
    [void]$lvOps.Items.Add($it)
    [void]$script:Ops.Add($op)
    [void]$script:Batch.Add($op)
    Write-Log "Disco $($info.Number) ($($info.Model), serial $($info.Serial)): iniciando $($MethodNames[$method])."
    $script:ChartOp = $op
    return $op
}

function Start-Ops($ops) {
    # Cria todas antes de executar, para que o resumo final saia uma vez só.
    $timer.Start()
    foreach ($o in $ops) { Step-Op $o }
}

function Complete-Stage($op) {
    $j = $op.Job
    $r = @{
        Mode = $j.Mode; Done = $j.Done; Total = $j.Total; Errors = $j.Errors; Slow = $j.Slow; Mismatch = $j.Mismatch
        Pattern = $j.PatternFirst; Error = $j.Error; Cancel = $j.Cancel; Seconds = ($j.Finished - $j.Started).TotalSeconds
        Offsets = @($j.ErrorOffsets)
        Bad = $j.BadSectors; Fixed = $j.FixedSectors; StillBad = $j.StillBad; BadOffsets = @($j.BadSectorOffsets)
        SeqRead = $j.SeqReadMBs; SeqWrite = $j.SeqWriteMBs; RndRead = $j.RndReadMBs; RndWrite = $j.RndWriteMBs
        RndReadIops = $j.RndReadIops; RndWriteIops = $j.RndWriteIops
        FakeChecked = $j.FakeChecked; FakeBad = $j.FakeBad; FakeFirstBad = $j.FakeFirstBad; DiskSize = $j.DiskSize
    }
    $op.Results[$j.Mode] = $r
    if ($j.Mode -in 'zero', 'read', 'sample', 'verify') { $op.Curve = $j.Curve; $op.CurveTitle = $StageNames[$j.Mode] }
    $op.Job = $null

    $failed = [bool]$r.Error -or $r.Cancel
    if ($j.Mode -in 'verify', 'verifysample' -and ($r.Mismatch -gt 0 -or $r.Errors -gt 0)) { $failed = $true }
    if ($r.Cancel) { $op.Cancelled = $true }
    if ($j.Mode -eq 'fakecheck' -and ($failed -or $r.FakeBad -gt 0)) { $op.Queue.Clear() }   # não formata disco falsificado
    if ($failed -and $op.Kind -eq 'wipe') {
        $op.Failed = $true
        $keep = @($op.Queue | Where-Object { $_ -eq 'cert' })
        $op.Queue.Clear(); foreach ($s in $keep) { $op.Queue.Enqueue($s) }
    }
    $msg = "Disco $($op.Info.Number): $($StageNames[$j.Mode]) - $(Format-Size $r.Done) em $(Format-Duration $r.Seconds)"
    if ($j.Mode -eq 'fakecheck') {
        $msg = "Disco $($op.Info.Number): teste de capacidade - $($r.FakeChecked) amostras conferidas, $($r.FakeBad) com erro, em $(Format-Duration $r.Seconds)"
    }
    if ($j.Mode -eq 'bench') {
        $msg = ("Disco {0}: benchmark - seq. leitura {1:N0} MB/s, seq. gravação {2:N0} MB/s, 4K leitura {3:N1} MB/s ({4:N0} IOPS), 4K gravação {5:N1} MB/s ({6:N0} IOPS)" -f
                $op.Info.Number, $r.SeqRead, $r.SeqWrite, $r.RndRead, $r.RndReadIops, $r.RndWrite, $r.RndWriteIops)
    }
    if ($j.Mode -in 'read', 'sample', 'verify', 'verifysample') { $msg += ", ilegíveis: $($r.Errors), lentos: $($r.Slow)" }
    if ($j.Mode -in 'verify', 'verifysample') { $msg += ", divergentes: $($r.Mismatch)" }
    if ($j.Mode -eq 'repair') {
        $msg += ", setores ilegíveis: $($r.Bad), reparados: $($r.Fixed), ainda ruins: $($r.StillBad)"
        if ($r.BadOffsets.Count) {
            $lbas = ($r.BadOffsets | Select-Object -First 30 | ForEach-Object { 'LBA {0}' -f [int64]($_ / 512) }) -join ', '
            Write-Log "Disco $($op.Info.Number): setores ilegíveis encontrados (primeiros): $lbas"
        }
    }
    if ($r.Error) { $msg += ". ERRO: $($r.Error)" }
    if ($r.Cancel) { $msg += '. CANCELADO.' }
    Write-Log $msg
}

# Trava de reentrância: as atualizações de tela (DoEvents/MessageBox) deixam o timer disparar no meio de
# uma etapa; sem a trava, a mesma operação avançava duas vezes e as etapas saíam fora de ordem.
function Step-Op($op) {
    if ($op.Busy -or -not $op.Active) { return }
    $op.Busy = $true
    try { Step-OpCore $op } finally { $op.Busy = $false }
}

function Step-OpCore($op) {
    while ($true) {
        if ($op.SelfTest) {
            $done = $false
            try { $done = Update-SelfTest $op }
            catch { $op.Results['selftest'] = @{ Passed = $null; Text = "Erro ao consultar: $($_.Exception.Message)" }; $done = $true }
            if (-not $done) { return }
            $op.SelfTest = $null
            Write-Log "Disco $($op.Info.Number): autoteste SMART terminou - $($op.Results['selftest'].Text)"
            if ($op.Cancelled) { $op.Queue.Clear() }   # diagnóstico completo cancelado: não segue para a leitura
        }
        if ($op.Job) {
            if ($op.Job.Running) { return }
            Complete-Stage $op
        }
        if ($op.Queue.Count -eq 0) { Close-Op $op; return }
        $stage = $op.Queue.Dequeue()
        $op.Stage = $stage
        $op.Item.SubItems[3].Text = $StageNames[$stage]
        [Windows.Forms.Application]::DoEvents()
        $num = $op.Info.Number
        try {
            switch ($stage) {
                'clear' {
                    Clear-TargetDisk $num
                    $op.Results['clear'] = @{ Ok = $true }
                    Write-Log "Disco $($num): partições removidas."
                }
                'format' {
                    $isFlash = ($op.Info.Tipo -in 'SSD', 'NVMe')
                    try {
                        $op.Letter = Initialize-AndFormat $num $op.Opts.Style $op.Opts.Fs $op.Opts.Label $isFlash
                        Write-Log "Disco $($num): formatado em $($op.Opts.Fs) como $($op.Letter):"
                    } catch {
                        $op.FormatError = $_.Exception.Message
                        Write-Log "Disco $($num): erro ao formatar: $($op.FormatError)"
                    }
                }
                'cert' { New-WipeCertificate $op }
                'selftest' {
                    $started = $false
                    try { Start-SelfTest $op; $started = $true }
                    catch { $op.Results['selftest'] = @{ Passed = $null; Text = $_.Exception.Message; Error = $true }; Write-Log "Disco $($num): $($_.Exception.Message)" }
                    if ($started) { return }
                }
                default {
                    $j = New-Object DiskJob
                    $j.Disk = $num; $j.Mode = $stage; $j.DiskSize = $op.Info.Size
                    if ($stage -eq 'bench') {
                        $j.BenchPath = $op.Opts.Path; $j.BenchSizeMB = $op.Opts.SizeMB
                    } else {
                        $real = [int64](Get-Disk -Number $num).Size
                        if ($op.Info.Size -le 0 -or $real -ne $op.Info.Size) {
                            throw "O disco informa $real bytes (esperado $($op.Info.Size)). Operação interrompida por segurança."
                        }
                    }
                    if ($stage -eq 'repair') {
                        foreach ($b in $op.Opts.Blocks) { $j.RepairBlocks.Add([int64]$b) }
                        $j.VolumeLetters = [string[]]@($op.Opts.Letters)
                        $j.SectorSize = [int]$op.Opts.SectorSize
                    }
                    $j.Start()
                    $op.Job = $j
                    return
                }
            }
        } catch {
            Write-Log "Disco $($num): ERRO em '$($StageNames[$stage])': $($_.Exception.Message)"
            $op.Failed = $true
            if ($stage -ne 'cert') {
                $keep = @($op.Queue | Where-Object { $_ -eq 'cert' })
                $op.Queue.Clear(); foreach ($s in $keep) { $op.Queue.Enqueue($s) }
            }
        }
    }
}

function Get-ReadResultText($op, $r) {
    $speed = 0; if ($r.Seconds -gt 0) { $speed = $r.Done / 1MB / $r.Seconds }
    if ($r.Error) { $res = "Erro: $($r.Error)" }
    elseif ($r.Errors -gt 0) { $res = "RUIM: $($r.Errors) bloco(s) ilegível(is), $($r.Slow) lento(s)" }
    elseif ($r.Slow -gt 20) { $res = "ATENÇÃO: $($r.Slow) bloco(s) muito lento(s)" }
    else { $res = "OK - sem erros ({0:N0} MB/s)" -f $speed }
    if ($r.Cancel) { $res = "Cancelado - parcial: $res" }
    if ($r.Errors -gt 0) {
        $pos = ($r.Offsets | Select-Object -First 20 | ForEach-Object { '{0:N0} MB' -f ($_ / 1MB) }) -join ', '
        Write-Log "Disco $($op.Info.Number): posições com erro (primeiras): $pos"
    }
    return $res
}

function Get-SelfTestResultText($r) {
    if (-not $r) { return 'Erro: sem resultado' }
    if ($r.Cancel) { return 'CANCELADO' }
    if ($r.Error) { return "Erro: $($r.Text)" }
    if ($r.Passed -eq $true) { return "APROVADO - $($r.Text)" }
    if ($r.Passed -eq $false) { return "RUIM: REPROVADO - $($r.Text)" }
    return "ATENÇÃO: $($r.Text)"
}

function Close-Op($op) {
    if ($op.Closed) { return }
    $op.Closed = $true
    $op.Active = $false
    $i = $op.Info
    $res = ''
    if ($op.Kind -eq 'test') {
        $r = $op.Results[$op.Method]
        if ($r) { $res = Get-ReadResultText $op $r }
    } elseif ($op.Kind -eq 'selftest') {
        $res = Get-SelfTestResultText $op.Results['selftest']
    } elseif ($op.Kind -eq 'diag') {
        # Diagnóstico completo: SMART + autoteste curto + leitura por amostragem; o pior resultado manda.
        $parts = New-Object System.Collections.ArrayList
        $smartTxt = switch ($i.Verdict) {
            'Crítico' { "RUIM: $(@($i.Reasons)[0])" } 'Atenção' { "ATENÇÃO: $(@($i.Reasons)[0])" }
            'Bom' { 'OK' + $(if ($null -ne $i.HealthPct) { " - saúde $($i.HealthPct)%" } else { '' }) }
            default { 'ATENÇÃO: sem dados SMART suficientes para avaliar a saúde (comum em gavetas/adaptadores USB)' }
        }
        [void]$parts.Add(@{ Method = 'smart'; Name = 'Análise SMART'; Text = $smartTxt })
        $st = $op.Results['selftest']
        if ($op.Opts.SelfTestSkip) { [void]$parts.Add(@{ Method = 'selftest_short'; Name = 'Autoteste SMART curto'; Text = "Não disponível - $($op.Opts.SelfTestSkip)" }) }
        elseif ($st -and $st.Error) { [void]$parts.Add(@{ Method = 'selftest_short'; Name = 'Autoteste SMART curto'; Text = "Não disponível - $($st.Text)" }) }
        elseif ($st) { [void]$parts.Add(@{ Method = 'selftest_short'; Name = 'Autoteste SMART curto'; Text = (Get-SelfTestResultText $st) }) }
        $rs = $op.Results['sample']
        if ($rs) { [void]$parts.Add(@{ Method = 'sample'; Name = 'Teste rápido (leitura por amostragem)'; Text = (Get-ReadResultText $op $rs) }) }
        elseif (-not $op.Cancelled) { [void]$parts.Add(@{ Method = 'sample'; Name = 'Teste rápido (leitura por amostragem)'; Text = 'Erro: o teste não chegou a rodar - veja o Log' }) }
        $op.SubResults = @($parts)
        $txts = @($parts | ForEach-Object { $_.Text })
        if ($op.Cancelled) { $res = 'CANCELADO' }
        elseif ($txts -match '^RUIM') { $res = 'RUIM: ' + (@($parts | Where-Object { $_.Text -match '^RUIM' })[0].Name) + ' reprovou' }
        elseif ($txts -match '^(ATENÇÃO|Erro)') { $res = 'ATENÇÃO: ' + ((@($parts | Where-Object { $_.Text -match '^(ATENÇÃO|Erro)' }) | ForEach-Object { $_.Name }) -join ', ') + ' com alerta' }
        elseif ($st -and -not $st.Error -and -not $op.Opts.SelfTestSkip) { $res = 'APROVADO - SMART, autoteste e leitura sem problemas' }
        else { $res = 'APROVADO - SMART e leitura sem problemas (autoteste indisponível neste disco)' }
    } elseif ($op.Kind -eq 'capacity') {
        $r = $op.Results['fakecheck']
        if (-not $r) { $res = 'Erro: o teste não chegou a rodar - veja o Log' }
        elseif ($r.Error) { $res = "Erro: $($r.Error)" }
        elseif ($r.Cancel) { $res = 'CANCELADO (o disco ficou sem partições)' }
        elseif ($r.FakeBad -eq 0) {
            $res = "OK - capacidade real confere ($(Format-Size $r.DiskSize), $($r.FakeChecked) amostras)"
            if ($op.Letter) { $res += " - unidade $($op.Letter):" }
        } else {
            $real = [Math]::Max(0, $r.FakeFirstBad)
            $res = "RUIM: FALSIFICADO ou com defeito - anuncia $(Format-Size $r.DiskSize), funciona só até ~$(Format-Size $real) ($($r.FakeBad) de $($r.FakeChecked) amostras falharam)"
        }
    } elseif ($op.Kind -eq 'bench') {
        $r = $op.Results['bench']
        if (-not $r) { $res = 'Erro: sem resultado' }
        elseif ($r.Error) { $res = "Erro: $($r.Error)" }
        elseif ($r.Cancel) { $res = 'CANCELADO' }
        else {
            $res = ('Seq: leitura {0:N0} / gravação {1:N0} MB/s | 4K: leitura {2:N1} MB/s ({3:N0} IOPS) / gravação {4:N1} MB/s ({5:N0} IOPS)' -f
                    $r.SeqRead, $r.SeqWrite, $r.RndRead, $r.RndReadIops, $r.RndWrite, $r.RndWriteIops)
        }
    } elseif ($op.Kind -eq 'repair') {
        $r = $op.Results['repair']
        if (-not $r -or $r.Error) { $res = "Erro: $($r.Error)" }
        else {
            if ($r.Bad -eq 0) { $res = 'Nenhum setor ilegível encontrado (o disco já os realocou sozinho)' }
            elseif ($r.StillBad -eq 0) { $res = "$($r.Fixed) setor(es) reparado(s) - rode chkdsk /f na unidade" }
            elseif ($r.Fixed -gt 0) { $res = "ATENÇÃO: $($r.Fixed) reparado(s), $($r.StillBad) ainda ilegível(is)" }
            else { $res = "RUIM: $($r.StillBad) setor(es) não puderam ser reparados - substitua o disco" }
            if ($r.Cancel) { $res = "Cancelado - parcial: $res" }
        }
    } else {
        if ($op.Cancelled) { $res = 'CANCELADO' }
        elseif ($op.Failed) { $res = 'FALHOU - veja o Log' }
        else {
            $res = 'Concluído'
            if ($op.Results['verify'] -or $op.Results['verifysample']) { $res = 'Concluído e verificado' }
            if ($op.Letter) { $res += " - unidade $($op.Letter):" }
            if ($op.FormatError) { $res += ' (erro ao formatar)' }
        }
    }
    $op.ResultText = $res
    $op.Summary = "Disco $($i.Number) ($($i.Model)) - $($MethodNames[$op.Method]): $res"
    $op.Item.SubItems[3].Text = 'Finalizado'
    $op.Item.SubItems[6].Text = ''
    $op.Item.SubItems[7].Text = $res
    if ($op.Failed -or $op.Cancelled -or $res -match '^(RUIM|Erro)') { $op.RowKind = 'bad' }
    elseif ($res -match '^ATENÇÃO') { $op.RowKind = 'warn' }
    else { $op.RowKind = 'ok' }
    $op.Item.BackColor = @{ ok = $script:Pal.RowOk; warn = $script:Pal.RowWarn; bad = $script:Pal.RowBad }[$op.RowKind]
    Write-Log $op.Summary

    if (-not (Get-ActiveOps).Count) {
        $timer.Stop()
        $progress.Value = 0
        $lblStatus.Text = 'Todas as operações terminaram.'
        $lines = @($script:Batch | ForEach-Object { '- ' + $_.Summary })
        $certs = @($script:Batch | Where-Object { $_.CertPath })
        $diags = @($script:Batch | Where-Object { $_.Kind -eq 'diag' -and -not $_.Cancelled })
        $script:Batch.Clear()
        $pic.Invalidate()
        Update-DiskList
        # Diagnóstico completo: laudo em PDF gerado automaticamente, com os dados SMART relidos agora
        foreach ($d in $diags) {
            try {
                $fresh = @($script:Disks | Where-Object { $_.Serial -eq $d.Info.Serial -and $_.Size -eq $d.Info.Size }) | Select-Object -First 1
                if (-not $fresh) { $fresh = $d.Info }
                $d.LaudoPath = New-DiskLaudo $fresh $d.Opts.Cliente $d.Opts.OS @($d)
                $certs += [pscustomobject]@{ CertPath = $d.LaudoPath }
            } catch { Write-Log "Disco $($d.Info.Number): erro ao gerar o laudo: $($_.Exception.Message)" }
        }
        $msg = ($lines -join "`r`n")
        if ($chkBench.Checked -and $diags.Count -and $diags.Count -eq $lines.Count) {
            # Modo bancada: sem janela que trave a fila - avisa na barra de status e com som
            $bad = @($diags | Where-Object { $_.ResultText -match '^(RUIM|ATENÇÃO)' })
            $lblStatus.Text = "Modo bancada: " + (($diags | ForEach-Object { "disco $($_.Info.Number) $(($_.ResultText -split ' - ')[0])" }) -join ' | ') +
                              ' - laudo(s) salvo(s) na pasta Laudos. Pode desconectar.'
            try { if ($bad.Count) { [Media.SystemSounds]::Exclamation.Play() } else { [Media.SystemSounds]::Asterisk.Play() } } catch { }
            return
        }
        if ($certs.Count -and $diags.Count) {
            $msg += "`r`n`r`nLaudo(s) técnico(s) salvo(s) na pasta Laudos" + $(if (@($certs | Where-Object { $_.CertPath -notlike '*\Laudos\*' }).Count) { ' e certificado(s) na pasta Certificados' } else { '' }) + '. Abrir agora?'
            if ((Show-Msg $msg 'Information' 'YesNo') -eq 'Yes') { foreach ($c in $certs) { Start-Process $c.CertPath } }
        }
        elseif ($certs.Count) { $msg += "`r`n`r`nCertificado(s) salvo(s) na pasta Certificados. Abrir agora?" ; if ((Show-Msg $msg 'Information' 'YesNo') -eq 'Yes') { foreach ($c in $certs) { Start-Process $c.CertPath } } }
        else { Show-Msg $msg | Out-Null }
    }
}

function Update-OpItem($op) {
    if ($op.SelfTest) {
        $st = $op.SelfTest
        $op.Item.SubItems[4].Text = $(if ($st.SeenRunning -and $null -ne $st.Percent) { "$($st.Percent)%" } else { '...' })
        $op.Item.SubItems[5].Text = ''
        $op.Item.SubItems[6].Text = "decorrido $(Format-Duration ((Get-Date) - $st.Started).TotalSeconds)"
        $op.Item.SubItems[7].Text = 'O disco está se testando; pode continuar usando o PC.'
        return
    }
    $j = $op.Job
    if (-not $j) { return }
    $elapsed = ((Get-Date) - $j.Started).TotalSeconds
    if ($j.Mode -eq 'erase') {
        $op.Item.SubItems[4].Text = '...'
        $op.Item.SubItems[5].Text = ''
        $op.Item.SubItems[6].Text = "decorrido $(Format-Duration $elapsed)"
        return
    }
    if ($j.Mode -eq 'fakecheck') {
        $op.Item.SubItems[3].Text = $j.Phase
        $op.Item.SubItems[4].Text = '{0:N0}%' -f ($j.Done * 100 / [Math]::Max(1, $j.Total))
        $op.Item.SubItems[5].Text = ''
        $op.Item.SubItems[7].Text = "amostras conferidas: $($j.FakeChecked)  com erro: $($j.FakeBad)"
        return
    }
    if ($j.Mode -eq 'bench') {
        $op.Item.SubItems[3].Text = $j.Phase
        $op.Item.SubItems[4].Text = '{0:N0}%' -f ($j.Done / 4)
        $parts = @()
        if ($j.SeqWriteMBs -gt 0) { $parts += 'Seq G {0:N0}' -f $j.SeqWriteMBs }
        if ($j.SeqReadMBs -gt 0)  { $parts += 'Seq L {0:N0}' -f $j.SeqReadMBs }
        if ($j.RndReadMBs -gt 0)  { $parts += '4K L {0:N1}' -f $j.RndReadMBs }
        $op.Item.SubItems[7].Text = ($parts -join ' | ') + $(if ($parts.Count) { ' MB/s' } else { '' })
        return
    }
    if ($j.Total -le 0) { return }
    $pct = $j.Done / $j.Total
    $op.Item.SubItems[4].Text = '{0:N1}%' -f ($pct * 100)
    if ($elapsed -gt 1 -and $j.Done -gt 0) {
        $op.Item.SubItems[5].Text = '{0:N0} MB/s' -f ($j.Done / 1MB / $elapsed)
        $op.Item.SubItems[6].Text = Format-Duration (($j.Total - $j.Done) / ($j.Done / $elapsed))
    }
    if ($j.Mode -in 'read', 'sample', 'verify', 'verifysample') {
        $t = "ilegíveis: $($j.Errors)  lentos: $($j.Slow)"
        if ($j.Mode -like 'verify*') { $t += "  divergentes: $($j.Mismatch)" }
        $op.Item.SubItems[7].Text = $t
    }
    if ($j.Mode -eq 'repair') {
        $op.Item.SubItems[7].Text = "ilegíveis: $($j.BadSectors)  reparados: $($j.FixedSectors)  ainda ruins: $($j.StillBad)"
    }
}

# ----- Proteção térmica: pausa leitura/gravação longas se o disco esquentar demais
function Get-TempLimit([string]$tipo) {
    switch ($tipo) { 'HDD' { return @(55, 50) } 'SSD' { return @(70, 62) } 'NVMe' { return @(78, 70) } default { return @(60, 52) } }
}

function Get-DiskTemperature($info) {
    try {
        $p = Get-PhysicalDisk -ErrorAction Stop | Where-Object { $_.DeviceId -eq "$($info.Number)" } | Select-Object -First 1
        if ($p) { $r = $p | Get-StorageReliabilityCounter -ErrorAction Stop; if ($r.Temperature -gt 0) { return [int]$r.Temperature } }
    } catch { }
    if ($info.SmartDevArgs) {
        try {
            $j = (Invoke-Smartctl (@('-j', '-A') + $info.SmartDevArgs)) | ConvertFrom-Json
            if ($j.temperature -and $j.temperature.current) { return [int]$j.temperature.current }
        } catch { }
    }
    return $null
}

function Update-ThermalGuard($op) {
    $j = $op.Job
    if (-not $j -or $j.Mode -notin 'zero', 'read', 'sample', 'verify', 'verifysample', 'bench') { return }
    if (-not $chkThermal.Checked) {
        if ($j.Pause) { $j.Pause = $false; $op.TempPaused = $false; Write-Log "Disco $($op.Info.Number): proteção térmica desligada, retomando." }
        return
    }
    if ((Get-Date) -lt $op.NextTempCheck) { return }
    $op.NextTempCheck = (Get-Date).AddSeconds(30)
    $t = Get-DiskTemperature $op.Info
    if ($null -eq $t) { return }
    $op.LastTemp = $t
    $lim = Get-TempLimit $op.Info.Tipo
    if (-not $j.Pause -and $t -ge $lim[0]) {
        $j.Pause = $true; $op.TempPaused = $true; $op.NextTempCheck = (Get-Date).AddSeconds(15)
        Write-Log "Disco $($op.Info.Number): PAUSADO por temperatura ($t °C, limite $($lim[0]) °C). Retoma abaixo de $($lim[1]) °C."
    } elseif ($j.Pause -and $t -le $lim[1]) {
        $j.Pause = $false; $op.TempPaused = $false
        Write-Log "Disco $($op.Info.Number): temperatura normalizada ($t °C), retomando."
    }
}

$timer.Add_Tick({
    if ($script:InTick) { return }
    $script:InTick = $true
    try {
        $active = @(Get-ActiveOps)
        $sum = 0.0; $n = 0
        foreach ($op in $active) {
            try { Step-Op $op } catch { Write-Log "Erro interno: $($_.Exception.Message)" }
            if ($op.Active) {
                try { Update-ThermalGuard $op } catch { }
                Update-OpItem $op
                if ($op.TempPaused) {
                    $op.Item.SubItems[5].Text = ''
                    $op.Item.SubItems[7].Text = "PAUSADO - $($op.LastTemp) °C, aguardando o disco esfriar"
                }
                if ($op.Job -and $op.Job.Total -gt 0) { $sum += $op.Job.Done / $op.Job.Total; $n++ }
            }
        }
        if ($n) {
            $progress.Value = [Math]::Min(1000, [int]($sum / $n * 1000))
            $lblStatus.Text = "$(@(Get-ActiveOps).Count) operação(ões) em andamento..."
        }
        if ($tabs.SelectedTab -eq $tabChart) { $pic.Invalidate() }
    } finally { $script:InTick = $false }
})

# ----- Gráfico de velocidade
$pic.Add_Paint({
    param($s, $e)
    $g = $e.Graphics
    $g.SmoothingMode = 'AntiAlias'
    $w = $pic.ClientSize.Width; $h = $pic.ClientSize.Height
    $op = $script:ChartOp
    $curve = $null; $title = 'Execute um teste de leitura ou uma zeragem para ver o gráfico.'
    if ($op) {
        if ($op.Job -and $op.Job.Mode -in 'zero', 'read', 'sample', 'verify') { $curve = $op.Job.Curve; $title = $StageNames[$op.Job.Mode] }
        elseif ($op.Curve) { $curve = $op.Curve; $title = $op.CurveTitle }
        $title = "Disco $($op.Info.Number) - $($op.Info.Model) - $title"
    }
    $fontT = New-Object Drawing.Font('Segoe UI', 9, [Drawing.FontStyle]::Bold)
    $fontA = New-Object Drawing.Font('Segoe UI', 8)
    $brText = New-Object Drawing.SolidBrush $script:Pal.ChartText; $brDim = New-Object Drawing.SolidBrush $script:Pal.ChartDim
    $g.Clear($script:Pal.ChartBack)
    $g.DrawString($title, $fontT, $brText, (S 10), (S 6))
    if (-not $curve) { return }
    $vals = @($curve | Where-Object { $_ -gt 0 })
    if (-not $vals.Count) { return }
    $max = ($vals | Measure-Object -Maximum).Maximum * 1.1
    $avg = ($vals | Measure-Object -Average).Average
    $l = S 60; $t = S 30; $r = $w - (S 20); $b = $h - (S 28)
    if ($r -le $l -or $b -le $t) { return }
    $gridPen = New-Object Drawing.Pen($script:Pal.ChartGrid)
    foreach ($k in 0..4) {
        $y = $b - ($b - $t) * $k / 4
        $g.DrawLine($gridPen, $l, $y, $r, $y)
        $g.DrawString(('{0:N0} MB/s' -f ($max * $k / 4)), $fontA, $brDim, (S 2), $y - (S 7))
    }
    foreach ($k in 0..4) {
        $x = $l + ($r - $l) * $k / 4
        $g.DrawString("$($k * 25)%", $fontA, $brDim, $x - (S 10), $b + (S 5))
    }
    $pts = New-Object System.Collections.Generic.List[Drawing.PointF]
    for ($k = 0; $k -lt $curve.Length; $k++) {
        if ($curve[$k] -gt 0) {
            $x = $l + ($r - $l) * ($k + 0.5) / $curve.Length
            $y = $b - ($b - $t) * $curve[$k] / $max
            $pts.Add((New-Object Drawing.PointF([float]$x, [float]$y)))
        }
    }
    $pen = New-Object Drawing.Pen($script:Pal.ChartLine, [float](S 2))
    if ($pts.Count -ge 2) { $g.DrawLines($pen, $pts.ToArray()) }
    elseif ($pts.Count -eq 1) { $g.FillEllipse([Drawing.Brushes]::RoyalBlue, $pts[0].X - 3, $pts[0].Y - 3, 6, 6) }
    $ya = $b - ($b - $t) * $avg / $max
    $avgPen = New-Object Drawing.Pen([Drawing.Color]::FromArgb(22, 163, 74)); $avgPen.DashStyle = 'Dash'
    $g.DrawLine($avgPen, $l, $ya, $r, $ya)
    $g.DrawString(('média {0:N0} MB/s' -f $avg), $fontA, (New-Object Drawing.SolidBrush $script:Pal.ChartAvg), $r - (S 110), $ya - (S 15))
    $g.DrawString('posição no disco', $fontA, $brDim, ($l + $r) / 2 - (S 40), $b + (S 14))
})
$pic.Add_Resize({ $pic.Invalidate() })

# ----- Gráfico do histórico: evolução de saúde/desgaste, dados gravados e temperatura ao longo do tempo
function Get-HistSeries($hist, [string]$field, [scriptblock]$map) {
    $pts = New-Object System.Collections.ArrayList
    foreach ($s in $hist) {
        if ($null -eq $s.$field -or "$($s.$field)" -eq '') { continue }
        try { $d = [datetime]$s.Data; $v = [double]$s.$field } catch { continue }
        if ($map) { $v = & $map $v }
        [void]$pts.Add([pscustomobject]@{ D = $d; V = $v })
    }
    return @($pts)
}

function Draw-HistPanel($g, [Drawing.Rectangle]$box, [string]$title, $pts, [string]$unit, [Drawing.Color]$color,
                        [Nullable[double]]$fixMin, [Nullable[double]]$fixMax, [datetime]$d0, [datetime]$d1) {
    $fontT = New-Object Drawing.Font('Segoe UI', 9, [Drawing.FontStyle]::Bold); $fontA = New-Object Drawing.Font('Segoe UI', 8)
    $brText = New-Object Drawing.SolidBrush $script:Pal.ChartText; $brDim = New-Object Drawing.SolidBrush $script:Pal.ChartDim
    $last = ''; if ($pts.Count) { $last = '   atual: ' + ('{0:N1}' -f $pts[-1].V).Replace(',0', '') + $unit }
    $g.DrawString("$title$last", $fontT, $brText, $box.X, $box.Y)
    $l = $box.X + (S 44); $t = $box.Y + (S 22); $r = $box.Right - (S 8); $b = $box.Bottom - (S 18)
    if ($r -le $l + 10 -or $b -le $t + 10) { return }
    if (-not $pts.Count) { $g.DrawString('sem dados para este disco', $fontA, $brDim, $l, $t + (S 10)); return }
    $vals = @($pts | ForEach-Object { $_.V })
    $mn = ($vals | Measure-Object -Minimum).Minimum; $mx = ($vals | Measure-Object -Maximum).Maximum
    if ($null -ne $fixMin) { $mn = [Math]::Min($mn, $fixMin) }
    if ($null -ne $fixMax) { $mx = [Math]::Max($mx, $fixMax) }
    if ($mx - $mn -lt 1e-9) { $pad = [Math]::Max(1, [Math]::Abs($mx) * 0.1); $mn -= $pad; $mx += $pad }
    else { $pad = ($mx - $mn) * 0.08; if ($null -eq $fixMin) { $mn -= $pad }; if ($null -eq $fixMax) { $mx += $pad } }
    $grid = New-Object Drawing.Pen($script:Pal.ChartGrid)
    foreach ($k in 0..3) {
        $y = $b - ($b - $t) * $k / 3
        $g.DrawLine($grid, $l, $y, $r, $y)
        $v = $mn + ($mx - $mn) * $k / 3
        $lbl = if ([Math]::Abs($mx - $mn) -ge 10) { '{0:N0}' -f $v } else { '{0:N1}' -f $v }
        $g.DrawString($lbl, $fontA, $brDim, $box.X, $y - (S 7))
    }
    $span = [Math]::Max(1.0, ($d1 - $d0).TotalSeconds)
    $X = { param($d) $l + ($r - $l) * (($d - $d0).TotalSeconds / $span) }
    $Y = { param($v) $b - ($b - $t) * (($v - $mn) / ($mx - $mn)) }
    $g.DrawString($d0.ToString('dd/MM/yy'), $fontA, $brDim, $l - (S 4), $b + (S 3))
    $endTxt = $d1.ToString('dd/MM/yy'); $sz = $g.MeasureString($endTxt, $fontA)
    $g.DrawString($endTxt, $fontA, $brDim, $r - $sz.Width + (S 4), $b + (S 3))
    $pen = New-Object Drawing.Pen($color, [float](S 2))
    $br = New-Object Drawing.SolidBrush $color
    $arr = @($pts | ForEach-Object { New-Object Drawing.PointF([float](& $X $_.D), [float](& $Y $_.V)) })
    if ($arr.Count -ge 2) { $g.DrawLines($pen, [Drawing.PointF[]]$arr) }
    $dot = [float](S 3)
    if ($arr.Count -le 60) { foreach ($p in $arr) { $g.FillEllipse($br, $p.X - $dot, $p.Y - $dot, 2 * $dot, 2 * $dot) } }
}

$picHist.Add_Paint({
    param($s, $e)
    $g = $e.Graphics; $g.SmoothingMode = 'AntiAlias'
    $g.Clear($script:Pal.ChartBack)
    $w = $picHist.ClientSize.Width; $h = $picHist.ClientSize.Height
    $i = $script:HistDisk; $hist = @($script:HistData)
    $fontT = New-Object Drawing.Font('Segoe UI', 9, [Drawing.FontStyle]::Bold)
    $brText = New-Object Drawing.SolidBrush $script:Pal.ChartText; $brDim = New-Object Drawing.SolidBrush $script:Pal.ChartDim
    if (-not $i) { $g.DrawString('Selecione um disco na lista.', $fontT, $brText, (S 10), (S 8)); return }
    $head = "Disco $($i.Number) - $($i.Model) - $($hist.Count) leitura(s) salva(s)"
    if ($hist.Count) { $head += " desde $(([datetime]$hist[0].Data).ToString('dd/MM/yyyy'))" }
    $g.DrawString($head, $fontT, $brText, (S 10), (S 6))
    if ($hist.Count -lt 2) {
        $g.DrawString('O gráfico aparece a partir da 2ª leitura. Uma leitura é salva ao abrir/atualizar o programa (até 1 por hora) - ' +
                      'ative o monitoramento diário em Configurações para acompanhar o disco mesmo sem abrir o DiskTool.',
                      (New-Object Drawing.Font('Segoe UI', 8.5)), $brDim, (New-Object Drawing.RectangleF((S 10), (S 30), ($w - (S 20)), (S 60))))
        if ($hist.Count -lt 1) { return }
    }
    Draw-HistCharts $g $w $h $(if ($hist.Count -lt 2) { S 80 } else { S 30 }) $i $hist
})
$picHist.Add_Resize({ $picHist.Invalidate() })

# Desenha os painéis (saúde ou setores, TB gravados, temperatura) - usado na aba e no laudo em PDF
function Draw-HistCharts($g, [int]$w, [int]$h, [int]$top, $i, $hist) {
    $d0 = [datetime]$hist[0].Data; $d1 = [datetime]$hist[-1].Data
    if (($d1 - $d0).TotalHours -lt 1) { $d1 = $d0.AddHours(1) }
    $panels = New-Object System.Collections.ArrayList
    if ($i.Tipo -eq 'HDD') {
        [void]$panels.Add(@('Setores realocados + pendentes', @(Get-HistSeries $hist 'Realocados'), '', [Drawing.Color]::FromArgb(220, 80, 60), 0, $null))
        $pend = @(Get-HistSeries $hist 'Pendentes')
        if ($pend.Count) {
            $re = @($panels[0][1])
            if ($re.Count -eq $pend.Count) { for ($k = 0; $k -lt $re.Count; $k++) { $re[$k] = [pscustomobject]@{ D = $re[$k].D; V = $re[$k].V + $pend[$k].V } } ; $panels[0][1] = $re }
        }
    } else {
        [void]$panels.Add(@('Saúde (vida útil restante)', @(Get-HistSeries $hist 'Desgaste' { param($v) [Math]::Max(0, 100 - $v) }), '%', [Drawing.Color]::FromArgb(40, 170, 90), $null, 100))
    }
    [void]$panels.Add(@('Total gravado', @(Get-HistSeries $hist 'TBGravados'), ' TB', $script:Pal.ChartLine, $null, $null))
    [void]$panels.Add(@('Temperatura', @(Get-HistSeries $hist 'Temp'), ' °C', [Drawing.Color]::FromArgb(230, 140, 30), $null, $null))
    $gap = S 16; $pw = [int](($w - (S 20) - $gap * ($panels.Count - 1)) / $panels.Count)
    for ($k = 0; $k -lt $panels.Count; $k++) {
        $p = $panels[$k]
        $box = New-Object Drawing.Rectangle(([int]((S 10) + $k * ($pw + $gap))), [int]$top, $pw, [int]($h - $top - (S 6)))
        Draw-HistPanel $g $box $p[0] @($p[1]) $p[2] $p[3] $p[4] $p[5] $d0 $d1
    }
}

# Gráfico do histórico como imagem PNG (base64) para o laudo - sempre no tema claro, próprio para impressão
function Get-HistChartBase64($i, $hist) {
    if (@($hist).Count -lt 2) { return $null }
    $savedPal = $script:Pal; $savedDark = $script:IsDark
    $bmp = $null; $g = $null
    try {
        Set-ThemePalette $false
        $w = S 960; $h = S 220
        $bmp = New-Object Drawing.Bitmap($w, $h)
        $g = [Drawing.Graphics]::FromImage($bmp); $g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'ClearTypeGridFit'
        $g.Clear([Drawing.Color]::White)
        Draw-HistCharts $g $w $h (S 6) $i @($hist)
        $ms = New-Object IO.MemoryStream
        $bmp.Save($ms, [Drawing.Imaging.ImageFormat]::Png)
        return [Convert]::ToBase64String($ms.ToArray())
    } catch { return $null }
    finally {
        if ($g) { $g.Dispose() }; if ($bmp) { $bmp.Dispose() }
        $script:Pal = $savedPal; $script:IsDark = $savedDark
    }
}

# ----- Eventos
$lv.Add_SelectedIndexChanged({
    if ($lv.SelectedItems.Count) {
        $i = $lv.SelectedItems[0].Tag
        $det = Get-HealthReport $i
        $prev = @(Get-PreviousLaudos $i)
        if ($prev.Count) {
            $det = "*** ESTE DISCO JÁ FOI DIAGNOSTICADO AQUI ($($prev.Count) laudo(s)) ***`r`n" +
                   ((Format-PreviousLaudos $prev | ForEach-Object { "   $_" }) -join "`r`n") + "`r`n`r`n" + $det
        }
        $txtDet.Text = $det
        $txtHist.Text = Get-HistoryText $i
        $script:HistDisk = $i; $script:HistData = @(Get-HealthHistory $i)
        $picHist.Invalidate()
    }
})

$lvOps.Add_SelectedIndexChanged({
    if ($lvOps.SelectedItems.Count) { $script:ChartOp = $lvOps.SelectedItems[0].Tag; $pic.Invalidate() }
})

$btnRefresh.Add_Click({ Update-DiskList })

# ----- Janela "Saúde detalhada" (estilo CrystalDiskInfo, com durabilidade/TBW)
$SmartNamesPt = @{
    1 = 'Taxa de erros de leitura'; 2 = 'Desempenho de throughput'; 3 = 'Tempo para girar'; 4 = 'Partidas/paradas do motor'
    5 = 'Setores realocados'; 7 = 'Taxa de erros de posicionamento'; 8 = 'Desempenho de posicionamento'; 9 = 'Horas ligado'
    10 = 'Tentativas de girar'; 11 = 'Tentativas de recalibração'; 12 = 'Ciclos liga/desliga'; 170 = 'Blocos reserva disponíveis'
    171 = 'Falhas de programação'; 172 = 'Falhas de apagamento'; 173 = 'Contagem média de apagamentos'; 174 = 'Desligamentos inesperados'
    177 = 'Nivelamento de desgaste'; 179 = 'Blocos reserva usados'; 180 = 'Blocos reserva restantes'; 181 = 'Falhas de programação'
    182 = 'Falhas de apagamento'; 183 = 'Erros de interface (downshift)'; 184 = 'Erros fim a fim'; 187 = 'Erros incorrigíveis reportados'
    188 = 'Comandos com tempo esgotado'; 189 = 'Gravações em altura elevada'; 190 = 'Temperatura do fluxo de ar'; 191 = 'Impactos (sensor G)'
    192 = 'Desligamentos de emergência'; 193 = 'Ciclos de carga do cabeçote'; 194 = 'Temperatura'; 195 = 'ECC corrigido por hardware'
    196 = 'Eventos de realocação'; 197 = 'Setores pendentes'; 198 = 'Setores incorrigíveis'; 199 = 'Erros de CRC (cabo/conexão)'
    200 = 'Taxa de erros de gravação'; 202 = 'Vida útil restante (%)'; 206 = 'Altura de voo do cabeçote'; 231 = 'Vida útil restante'
    232 = 'Reserva disponível'; 233 = 'Indicador de desgaste da mídia'; 235 = 'Contagem de falhas de energia'; 240 = 'Horas de voo do cabeçote'
    241 = 'Total gravado (computador)'; 242 = 'Total lido (computador)'; 246 = 'Total gravado (computador)'; 249 = 'Total gravado na NAND'
}

function Get-HealthColor([string]$verdict) {
    switch ($verdict) {
        'Bom'     { return [Drawing.Color]::FromArgb(140, 195, 255) }
        'Atenção' { return [Drawing.Color]::FromArgb(255, 215, 70) }
        'Crítico' { return [Drawing.Color]::FromArgb(255, 105, 105) }
        default   { return [Drawing.Color]::FromArgb(200, 200, 200) }
    }
}

function Get-TempColor($i) {
    if ($null -eq $i.Temp) { return [Drawing.Color]::FromArgb(200, 200, 200) }
    $lim = @(60, 70); if ($i.Tipo -eq 'HDD') { $lim = @(45, 55) }
    if ($i.Temp -lt $lim[0]) { return [Drawing.Color]::FromArgb(140, 195, 255) }
    if ($i.Temp -lt $lim[1]) { return [Drawing.Color]::FromArgb(255, 215, 70) }
    return [Drawing.Color]::FromArgb(255, 105, 105)
}

# Linhas da tabela SMART: Status = ok | warn | bad
function Get-SmartRows($i) {
    $rows = New-Object System.Collections.Generic.List[object]
    $j = $i.SmartJson
    $n = $null; if ($j) { $n = $j.nvme_smart_health_information_log }
    if ($j -and $j.ata_smart_attributes -and $j.ata_smart_attributes.table) {
        foreach ($a in $j.ata_smart_attributes.table) {
            $id = [int]$a.id
            $st = 'ok'
            if ($a.when_failed -eq 'now') { $st = 'bad' } elseif ($a.when_failed) { $st = 'warn' }
            elseif ($id -in 5, 196, 197, 198 -and [int64]$a.raw.value -gt 0) { $st = 'warn' }
            $name = $SmartNamesPt[$id]; if (-not $name) { $name = ([string]$a.name).Replace('_', ' ') }
            $rows.Add([pscustomobject]@{ Status = $st; Id = '{0:X2}' -f $id; Name = $name; Cur = $a.value; Worst = $a.worst; Thr = $a.thresh; Raw = [string]$a.raw.string })
        }
    } elseif ($n) {
        $tb = { param($u) '{0:N2} TB  ({1:N0} unidades)' -f ([double]$u * 512000 / 1e12), [double]$u }
        $defs = @(
            @('01', 'Aviso crítico', $n.critical_warning, $(if ($n.critical_warning -gt 0) { 'bad' } else { 'ok' })),
            @('02', 'Temperatura composta', "$($n.temperature) °C", 'ok'),
            @('03', 'Reserva disponível', "$($n.available_spare)%", $(if ($n.available_spare_threshold -gt 0 -and $n.available_spare -le $n.available_spare_threshold) { 'bad' } else { 'ok' })),
            @('04', 'Limite da reserva', "$($n.available_spare_threshold)%", 'ok'),
            @('05', 'Vida útil usada', "$($n.percentage_used)%", $(if ($n.percentage_used -ge 90) { 'bad' } elseif ($n.percentage_used -ge 70) { 'warn' } else { 'ok' })),
            @('06', 'Dados lidos', (& $tb $n.data_units_read), 'ok'),
            @('07', 'Dados gravados', (& $tb $n.data_units_written), 'ok'),
            @('08', 'Comandos de leitura', ('{0:N0}' -f [double]$n.host_reads), 'ok'),
            @('09', 'Comandos de gravação', ('{0:N0}' -f [double]$n.host_writes), 'ok'),
            @('0A', 'Tempo ocupado do controlador', "$($n.controller_busy_time) min", 'ok'),
            @('0B', 'Ciclos liga/desliga', $n.power_cycles, 'ok'),
            @('0C', 'Horas ligado', $n.power_on_hours, 'ok'),
            @('0D', 'Desligamentos inesperados', $n.unsafe_shutdowns, 'ok'),
            @('0E', 'Erros de mídia/integridade', $n.media_errors, $(if ($n.media_errors -gt 0) { 'warn' } else { 'ok' })),
            @('0F', 'Entradas no log de erros', $n.num_err_log_entries, 'ok')
        )
        foreach ($d in $defs) { $rows.Add([pscustomobject]@{ Status = $d[3]; Id = $d[0]; Name = $d[1]; Cur = ''; Worst = ''; Thr = ''; Raw = [string]$d[2] }) }
    } else {
        # Sem smartctl: só o que o Windows informa
        foreach ($d in @(@('Temperatura', (Show-Value $i.Temp ' °C')), @('Vida útil usada', (Show-Value $i.Wear '%')), @('Horas ligado', (Show-Value $i.PowerOnHours)),
                         @('Erros de leitura (total / não corrigidos)', "$(Show-Value $i.ReadErrTotal) / $(Show-Value $i.ReadErrUnc)"),
                         @('Erros de gravação (total / não corrigidos)', "$(Show-Value $i.WriteErrTotal) / $(Show-Value $i.WriteErrUnc)"),
                         @('Status de saúde (Windows)', (Show-Value $i.HealthStatus)))) {
            $rows.Add([pscustomobject]@{ Status = 'ok'; Id = '--'; Name = $d[0]; Cur = ''; Worst = ''; Thr = ''; Raw = [string]$d[1] })
        }
    }
    return $rows
}

function Show-HealthWindow([int]$startNumber) {
    $w = New-Object Windows.Forms.Form
    $w.SuspendLayout()
    $w.AutoScaleDimensions = New-Object Drawing.SizeF(96, 96); $w.AutoScaleMode = 'Dpi'
    $w.Text = 'Saúde detalhada dos discos'; $w.ClientSize = New-Object Drawing.Size(910, 684)
    $w.FormBorderStyle = 'FixedDialog'; $w.MaximizeBox = $false; $w.StartPosition = 'CenterParent'; $w.Font = $fontUI
    if ($form.Icon) { $w.Icon = $form.Icon }
    $script:hwForm = $w
    $script:hwNum = $startNumber

    $script:hwDisks = New-Object Windows.Forms.FlowLayoutPanel
    $script:hwDisks.Location = New-Object Drawing.Point(10, 6); $script:hwDisks.Size = New-Object Drawing.Size(890, 62); $script:hwDisks.AutoScroll = $true
    $script:hwTitle = New-Object Windows.Forms.Label
    $script:hwTitle.Location = New-Object Drawing.Point(10, 72); $script:hwTitle.Size = New-Object Drawing.Size(890, 26)
    $script:hwTitle.Font = New-Object Drawing.Font('Segoe UI', 13, [Drawing.FontStyle]::Bold); $script:hwTitle.TextAlign = 'MiddleCenter'

    $cap1 = New-Object Windows.Forms.Label; $cap1.Text = 'Estado de saúde'; $cap1.Location = New-Object Drawing.Point(10, 104); $cap1.Size = New-Object Drawing.Size(165, 18); $cap1.TextAlign = 'MiddleCenter'
    $script:hwHealth = New-Object Windows.Forms.Label
    $script:hwHealth.Location = New-Object Drawing.Point(10, 124); $script:hwHealth.Size = New-Object Drawing.Size(165, 82)
    $script:hwHealth.Font = New-Object Drawing.Font('Segoe UI', 16, [Drawing.FontStyle]::Bold); $script:hwHealth.TextAlign = 'MiddleCenter'; $script:hwHealth.BorderStyle = 'FixedSingle'
    $script:hwHealth.Name = 'keep'; $script:hwHealth.ForeColor = [Drawing.Color]::Black
    $cap2 = New-Object Windows.Forms.Label; $cap2.Text = 'Temperatura'; $cap2.Location = New-Object Drawing.Point(10, 212); $cap2.Size = New-Object Drawing.Size(165, 18); $cap2.TextAlign = 'MiddleCenter'
    $script:hwTemp = New-Object Windows.Forms.Label
    $script:hwTemp.Location = New-Object Drawing.Point(10, 232); $script:hwTemp.Size = New-Object Drawing.Size(165, 58)
    $script:hwTemp.Font = New-Object Drawing.Font('Segoe UI', 15, [Drawing.FontStyle]::Bold); $script:hwTemp.TextAlign = 'MiddleCenter'; $script:hwTemp.BorderStyle = 'FixedSingle'
    $script:hwTemp.Name = 'keep'; $script:hwTemp.ForeColor = [Drawing.Color]::Black

    # Grade de informações (rótulo / valor em duas colunas)
    $script:hwFields = @{}
    $left  = @('Firmware', 'Número de série', 'Interface', 'Padrão', 'Recursos', 'Letras')
    $right = @('Total lido', 'Total gravado', 'Rotação', 'Contagem de ligações', 'Horas ligado', 'Fonte dos dados')
    for ($r = 0; $r -lt 6; $r++) {
        foreach ($side in 0, 1) {
            $key = @($left, $right)[$side][$r]
            $x = 190 + $side * 360; $y = 104 + $r * 31
            $l = New-Object Windows.Forms.Label; $l.Text = "$($key):"; $l.Location = New-Object Drawing.Point($x, ($y + 4)); $l.Size = New-Object Drawing.Size(130, 20); $l.TextAlign = 'MiddleRight'
            $t = New-Object Windows.Forms.TextBox; $t.ReadOnly = $true; $t.BackColor = 'White'; $t.Location = New-Object Drawing.Point(($x + 135), $y); $t.Width = 215
            $w.Controls.AddRange(@($l, $t)); $script:hwFields[$key] = $t
        }
    }

    # Durabilidade
    $g = New-Object Windows.Forms.GroupBox; $g.Text = 'Durabilidade (TBW - total de dados que o fabricante garante que o disco aguenta gravar)'
    $g.Location = New-Object Drawing.Point(10, 298); $g.Size = New-Object Drawing.Size(890, 122)
    $script:hwDur1 = New-Object Windows.Forms.Label; $script:hwDur1.Location = New-Object Drawing.Point(12, 22); $script:hwDur1.Size = New-Object Drawing.Size(860, 20)
    $script:hwDur1.Font = New-Object Drawing.Font('Segoe UI', 9.5, [Drawing.FontStyle]::Bold)
    $script:hwBar = New-Object Windows.Forms.PictureBox; $script:hwBar.Location = New-Object Drawing.Point(12, 45); $script:hwBar.Size = New-Object Drawing.Size(862, 20)
    $script:hwDur2 = New-Object Windows.Forms.Label; $script:hwDur2.Location = New-Object Drawing.Point(12, 70); $script:hwDur2.Size = New-Object Drawing.Size(860, 20)
    $script:hwDur3 = New-Object Windows.Forms.Label; $script:hwDur3.Location = New-Object Drawing.Point(12, 93); $script:hwDur3.Size = New-Object Drawing.Size(690, 20); $script:hwDur3.ForeColor = 'DimGray'
    $btnTbw = New-Object Windows.Forms.Button; $btnTbw.Text = 'Definir TBW do fabricante...'; $btnTbw.Location = New-Object Drawing.Point(706, 88); $btnTbw.Size = New-Object Drawing.Size(168, 27)
    $g.Controls.AddRange(@($script:hwDur1, $script:hwBar, $script:hwDur2, $script:hwDur3, $btnTbw))

    $script:hwBar.Add_Paint({
        param($s, $e)
        $gr = $e.Graphics; $gr.SmoothingMode = 'AntiAlias'
        $wd = $script:hwBar.ClientSize.Width - 1; $ht = $script:hwBar.ClientSize.Height - 1
        $gr.Clear($script:Pal.Back)
        $gr.FillRectangle((New-Object Drawing.SolidBrush $script:Pal.BarBack), 0, 0, $wd, $ht)
        $i = $script:hwInfo
        $txt = 'TBW garantido desconhecido'
        if ($i -and $i.RatedTBW -and $null -eq $i.TBW) { $txt = 'Uso do TBW indisponível: o total gravado não é informado' }
        if ($i -and $null -ne $i.TbwUsedPct) {
            $pct = [Math]::Min(100, [double]$i.TbwUsedPct)
            $c = [Drawing.Color]::FromArgb(76, 175, 80); if ($pct -ge 90) { $c = [Drawing.Color]::FromArgb(229, 72, 72) } elseif ($pct -ge 70) { $c = [Drawing.Color]::FromArgb(240, 180, 40) }
            $gr.FillRectangle((New-Object Drawing.SolidBrush $c), 0, 0, [float]($wd * $pct / 100), $ht)
            $txt = '{0:N1}% do TBW usado' -f $i.TbwUsedPct
        } elseif ($i -and $i.Tipo -eq 'HDD') { $txt = 'HDD: a durabilidade é medida pelos setores realocados/pendentes, não por TBW' }
        $gr.DrawRectangle([Drawing.Pens]::Silver, 0, 0, $wd, $ht)
        $sf = New-Object Drawing.StringFormat; $sf.Alignment = 'Center'; $sf.LineAlignment = 'Center'
        $gr.DrawString($txt, $fontUI, (New-Object Drawing.SolidBrush $script:Pal.BarText), (New-Object Drawing.RectangleF(0, 0, $wd, $ht)), $sf)
    })

    # Tabela SMART com bolinhas de status
    $img = New-Object Windows.Forms.ImageList; $img.ImageSize = New-Object Drawing.Size(14, 14)
    foreach ($c in @([Drawing.Color]::FromArgb(60, 140, 230), [Drawing.Color]::FromArgb(240, 180, 30), [Drawing.Color]::FromArgb(220, 50, 50))) {
        $b = New-Object Drawing.Bitmap 14, 14; $gg = [Drawing.Graphics]::FromImage($b); $gg.SmoothingMode = 'AntiAlias'
        $gg.FillEllipse((New-Object Drawing.SolidBrush $c), 1, 1, 12, 12); $gg.Dispose(); $img.Images.Add($b)
    }
    $script:hwList = New-Object Windows.Forms.ListView
    $script:hwList.View = 'Details'; $script:hwList.FullRowSelect = $true; $script:hwList.GridLines = $true; $script:hwList.SmallImageList = $img
    $script:hwList.Location = New-Object Drawing.Point(10, 428); $script:hwList.Size = New-Object Drawing.Size(890, 210)
    foreach ($c in @(@('ID', 60), @('Atributo', 290), @('Atual', 60), @('Pior', 60), @('Limite', 60), @('Valor bruto', 320))) { [void]$script:hwList.Columns.Add($c[0], (S $c[1])) }

    $script:hwNote = New-Object Windows.Forms.Label; $script:hwNote.Location = New-Object Drawing.Point(10, 646); $script:hwNote.Size = New-Object Drawing.Size(520, 32); $script:hwNote.ForeColor = 'DimGray'
    $bRef = New-Object Windows.Forms.Button; $bRef.Text = 'Atualizar'; $bRef.Location = New-Object Drawing.Point(540, 646); $bRef.Size = New-Object Drawing.Size(100, 30)
    $bTxt = New-Object Windows.Forms.Button; $bTxt.Text = 'SMART em texto'; $bTxt.Location = New-Object Drawing.Point(646, 646); $bTxt.Size = New-Object Drawing.Size(140, 30)
    $bClose = New-Object Windows.Forms.Button; $bClose.Text = 'Fechar'; $bClose.Location = New-Object Drawing.Point(792, 646); $bClose.Size = New-Object Drawing.Size(108, 30); $bClose.DialogResult = 'Cancel'
    $w.CancelButton = $bClose

    $w.Controls.AddRange(@($script:hwDisks, $script:hwTitle, $cap1, $script:hwHealth, $cap2, $script:hwTemp, $g, $script:hwList, $script:hwNote, $bRef, $bTxt, $bClose))

    $bRef.Add_Click({ $script:hwForm.Cursor = 'WaitCursor'; Update-DiskList; Update-HealthWindow; $script:hwForm.Cursor = 'Default' })
    $bTxt.Add_Click({
        if (-not $script:hwInfo) { return }
        $script:hwForm.Cursor = 'WaitCursor'
        $tf = New-Object Windows.Forms.Form; $tf.Text = "SMART em texto - Disco $($script:hwInfo.Number)"; $tf.Size = New-Object Drawing.Size(900, 650); $tf.StartPosition = 'CenterParent'
        $tb = New-Object Windows.Forms.TextBox; $tb.Multiline = $true; $tb.ReadOnly = $true; $tb.ScrollBars = 'Both'; $tb.WordWrap = $false
        $tb.Dock = 'Fill'; $tb.Font = $fontMono; $tb.BackColor = 'White'; $tb.Text = Get-HealthReport $script:hwInfo -WithSmartctl
        $tf.Controls.Add($tb)
        $script:hwForm.Cursor = 'Default'
        $tf.Add_Load({ param($s, $e) Set-Theme $s })
        [void]$tf.ShowDialog($script:hwForm)
    })
    $btnTbw.Add_Click({
        $i = $script:hwInfo; if (-not $i) { return }
        Add-Type -AssemblyName Microsoft.VisualBasic
        $cur = ''; if ($i.RatedTBW -and $i.RatedSource -match 'informado') { $cur = "$($i.RatedTBW)" }
        $ans = [Microsoft.VisualBasic.Interaction]::InputBox(
            "Informe o TBW (em TB) da ficha técnica do fabricante para:`r`n`r`n$($i.Model)  ($(Format-Size $i.Size))`r`n`r`n" +
            "O valor fica salvo para este modelo. Deixe vazio e confirme para voltar ao valor automático.", 'TBW do fabricante', $cur)
        if ($null -eq $ans) { return }
        $ans = $ans.Trim()
        if (-not $ans) { Set-CustomTbw $i.Model $null; Write-Log "TBW personalizado removido: $($i.Model)" }
        else {
            $v = 0.0
            if (-not [double]::TryParse($ans.Replace(',', '.'), [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$v) -or $v -le 0) {
                Show-Msg 'Valor inválido. Informe só o número em TB, por exemplo: 600' 'Warning' | Out-Null; return
            }
            Set-CustomTbw $i.Model $v
            Write-Log "TBW do fabricante definido: $($i.Model) = $v TB"
        }
        $script:hwForm.Cursor = 'WaitCursor'; Update-DiskList; Update-HealthWindow; $script:hwForm.Cursor = 'Default'
    })

    $w.ResumeLayout($false)
    $w.Add_Load({ param($s, $e) Set-Theme $s })
    $w.Add_Shown({ Update-HealthWindow })
    [void]$w.ShowDialog($form)
    $script:hwInfo = $null
}

function Update-HealthWindow {
    $disks = @($script:Disks)
    if (-not $disks.Count) { return }
    $i = @($disks | Where-Object { $_.Number -eq $script:hwNum })[0]
    if (-not $i) { $i = $disks[0]; $script:hwNum = $i.Number }
    $script:hwInfo = $i

    # Botões dos discos (como as abas coloridas do CrystalDiskInfo)
    $script:hwDisks.SuspendLayout(); $script:hwDisks.Controls.Clear()
    foreach ($d in $disks) {
        $b = New-Object Windows.Forms.Button
        $b.Size = New-Object Drawing.Size(122, 52); $b.FlatStyle = 'Flat'; $b.BackColor = Get-HealthColor $d.Verdict
        $b.Name = 'keep'; $b.ForeColor = [Drawing.Color]::Black
        $where = $d.Letters; if (-not $where) { $where = "Disco $($d.Number)" }
        $b.Text = "$(Format-HealthLabel $d)`r`n$(Show-Value $d.Temp ' °C')`r`n$where"
        if ($d.Number -eq $i.Number) { $b.FlatAppearance.BorderSize = 3; $b.FlatAppearance.BorderColor = [Drawing.Color]::Black; $b.Font = New-Object Drawing.Font('Segoe UI', 8.5, [Drawing.FontStyle]::Bold) }
        else { $b.FlatAppearance.BorderSize = 1; $b.Font = New-Object Drawing.Font('Segoe UI', 8.5) }
        $b.Tag = $d.Number
        $b.Add_Click({ param($s, $e) $script:hwNum = [int]$s.Tag; Update-HealthWindow })
        $script:hwDisks.Controls.Add($b)
    }
    $script:hwDisks.ResumeLayout()

    $script:hwTitle.Text = "$($i.Model) : $(Format-Size $i.Size)"
    $hText = $i.Verdict; if ($null -ne $i.HealthPct -and $i.Verdict -notin 'Sem mídia', 'Sem dados') { $hText = "$($i.Verdict)`r`n$($i.HealthPct) %" }
    $script:hwHealth.Text = $hText; $script:hwHealth.BackColor = Get-HealthColor $i.Verdict
    $script:hwTemp.Text = (Show-Value $i.Temp ' °C'); $script:hwTemp.BackColor = Get-TempColor $i

    $iface = $i.Bus; if ($i.LinkSpeed) { $iface = "$($i.Bus) | $($i.LinkSpeed)" }
    $rot = 'n/d'; if ($i.Tipo -in 'SSD', 'NVMe' -or $i.Rpm -eq 0) { $rot = '---- (SSD)' } ; if ($i.Rpm -gt 0) { $rot = "$($i.Rpm) RPM" }
    $src = 'Windows (limitado)'; if ($i.SmartSource -eq 'smartctl') { $src = 'smartctl (SMART completo)' } elseif ($i.SmartSource -eq 'nvme') { $src = 'Log NVMe (leitura direta)' }
    $vals = @{
        'Firmware' = $i.Firmware; 'Número de série' = $i.Serial; 'Interface' = $iface; 'Padrão' = $i.Standard
        'Recursos' = $i.Features; 'Letras' = $i.Letters
        'Total lido' = $(if ($null -ne $i.TBR) { "$(Format-TB $i.TBR)" } else { 'n/d' })
        'Total gravado' = $(if ($null -ne $i.TBW) { "$(Format-TB $i.TBW)" } else { 'n/d' })
        'Rotação' = $rot; 'Contagem de ligações' = $(if ($null -ne $i.PowerCycles) { "$($i.PowerCycles) vezes" } else { 'n/d' })
        'Horas ligado' = $(if ($i.PowerOnHours) { '{0} horas (~{1:N0} dias)' -f $i.PowerOnHours, ($i.PowerOnHours / 24) } else { 'n/d' })
        'Fonte dos dados' = $src
    }
    foreach ($k in $vals.Keys) { $v = [string]$vals[$k]; if (-not $v) { $v = 'n/d' }; $script:hwFields[$k].Text = $v }

    # Durabilidade
    if ($i.Tipo -eq 'HDD') {
        $script:hwDur1.Text = 'HDD não tem limite de TBW como os SSDs.'
        $script:hwDur2.Text = "Setores realocados: $(Show-Value $i.Realloc)   |   pendentes: $(Show-Value $i.Pending)   |   incorrigíveis: $(Show-Value $i.Uncorr)"
        $script:hwDur3.Text = 'Em HDD, a saúde real é medida pelos setores ruins e pelo teste de leitura de superfície.'
    } else {
        if ($null -eq $i.TBW -and $i.RatedTBW) { $script:hwDur1.Text = "TBW garantido: $(Format-TB $i.RatedTBW)  -  o total já gravado não é informado por este disco/controlador" }
        elseif ($null -eq $i.TBW) { $script:hwDur1.Text = 'Total gravado: não informado por este disco/adaptador' }
        elseif ($i.RatedTBW) { $script:hwDur1.Text = "Total gravado: $(Format-TB $i.TBW) de $(Format-TB $i.RatedTBW) garantidos pelo fabricante" }
        else { $script:hwDur1.Text = "Total gravado: $(Format-TB $i.TBW)  (TBW garantido desconhecido - clique em 'Definir TBW do fabricante')" }
        $parts = @()
        if ($null -ne $i.HealthPct) { $parts += "Vida útil restante: $($i.HealthPct)%" }
        if ($i.WriteRateTBDay) { $parts += ('Ritmo: {0:N1} GB/dia ({1})' -f ($i.WriteRateTBDay * 1000), $i.RateSource) }
        if ($null -ne $i.RemainingYears) {
            if ($i.RemainingYears -gt 50) { $parts += 'Vida restante estimada: mais de 50 anos' } else { $parts += ('Vida restante estimada: ~{0:N1} anos ({1})' -f $i.RemainingYears, $i.RemainingBasis) }
        }
        $script:hwDur2.Text = ($parts -join '   |   ')
        $script:hwDur3.Text = $(if ($i.WearNote) { $i.WearNote } elseif ($i.RatedSource) { "Fonte do TBW: $($i.RatedSource)" } else { 'Fonte do TBW: modelo fora da tabela e sem desgaste suficiente para estimar.' })
    }
    $script:hwBar.Invalidate()

    $script:hwList.BeginUpdate(); $script:hwList.Items.Clear()
    foreach ($r in (Get-SmartRows $i)) {
        $it = New-Object Windows.Forms.ListViewItem($r.Id)
        $it.ImageIndex = @{ ok = 0; warn = 1; bad = 2 }[$r.Status]
        foreach ($v in @($r.Name, $r.Cur, $r.Worst, $r.Thr, $r.Raw)) { [void]$it.SubItems.Add([string]$v) }
        if ($r.Status -eq 'bad') { $it.BackColor = $script:Pal.RowBad } elseif ($r.Status -eq 'warn') { $it.BackColor = $script:Pal.RowWarn }
        [void]$script:hwList.Items.Add($it)
    }
    $script:hwList.EndUpdate()

    $note = ''
    if ($i.SmartError) {
        $note = "SMART completo indisponível: $($i.SmartError)"
        if ($RstController -and $i.Bus -in 'NVMe', 'RAID', 'SATA') { $note = 'SMART completo bloqueado pelo controlador Intel RST/VMD deste PC - exibindo só os dados do Windows.' }
    } elseif ($i.SmartSource -eq 'nvme') {
        $note = 'Dados lidos direto do log de saúde NVMe pelo Windows (o smartctl não tem acesso a este disco; o autoteste SMART fica indisponível).'
    } elseif (-not $SmartctlPath) { $note = 'smartctl não encontrado - exibindo só os dados do Windows.' }
    if ($i.Reasons.Count) { if ($note) { $note += "`r`n" }; $note += 'Motivo do diagnóstico: ' + $i.Reasons[0] }
    $script:hwNote.Text = $note
}

$btnSmart.Add_Click({
    $sel = @(Get-SelectedDisks); if (-not $sel.Count) { return }
    Show-HealthWindow $sel[0].Number
})
$lv.Add_DoubleClick({ if ($lv.SelectedItems.Count) { Show-HealthWindow $lv.SelectedItems[0].Tag.Number } })

function Test-DisksHaveMedia($disks) {
    $bad = @($disks | Where-Object { $_.Size -le 0 })
    if (-not $bad.Count) { return $true }
    $msg = (($bad | ForEach-Object { "Disco $($_.Number) ($($_.Model))" }) -join "`r`n") + "`r`n`r`n" +
           'informa capacidade de 0 bytes. Isso acontece com leitor de cartão vazio ou com pendrive/disco com defeito ' +
           '(o controlador entra em modo de segurança quando a memória falha). Não há o que testar ou apagar.'
    Show-Msg $msg 'Stop' | Out-Null
    return $false
}

function Start-ReadTests([string]$method) {
    $sel = @(Get-SelectedDisks); if (-not $sel.Count) { return }
    if (-not (Test-DisksHaveMedia $sel)) { return }
    $sel = @($sel | Where-Object { -not (Test-DiskBusy $_.Number) })
    if (-not $sel.Count) { Show-Msg 'Os discos selecionados já estão em uso por outra operação.' 'Warning' | Out-Null; return }
    $names = ($sel | ForEach-Object { "Disco $($_.Number) - $($_.Model) ($(Format-Size $_.Size))" }) -join "`r`n"
    $desc = 'Lê o disco inteiro. Pode levar horas em HDDs grandes (1 TB ≈ 1,5 a 3 h).'
    if ($method -eq 'sample') { $desc = 'Lê 2.000 blocos espalhados pelo disco. Leva poucos minutos e dá uma boa amostra.' }
    $r = Show-Msg "Iniciar teste em:`r`n$names`r`n`r`n$desc`r`nO teste NÃO altera nenhum dado." 'Question' 'YesNo'
    if ($r -ne 'Yes') { return }
    $new = @(foreach ($i in $sel) { New-Op $i 'test' $method @($method) $null })
    Start-Ops $new
    $tabs.SelectedTab = $tabChart
}
# ----- Diagnóstico completo: SMART + autoteste curto (se o disco permitir) + teste rápido + laudo em PDF
function Start-Diagnostics {
    $sel = @(Get-SelectedDisks); if (-not $sel.Count) { return }
    if (-not (Test-DisksHaveMedia $sel)) { return }
    $busy = @($sel | Where-Object { Test-DiskBusy $_.Number })
    $sel = @($sel | Where-Object { -not (Test-DiskBusy $_.Number) })
    if (-not $sel.Count) { Show-Msg 'Os discos selecionados já estão em uso por outra operação.' 'Warning' | Out-Null; return }
    $lines = foreach ($i in $sel) {
        $st = 'autoteste curto + leitura por amostragem'
        if (-not $SmartctlPath -or -not $i.SmartDevArgs) { $st = 'leitura por amostragem (autoteste indisponível neste disco)' }
        "Disco $($i.Number) - $($i.Model) ($(Format-Size $i.Size)): $st"
        $prev = @(Get-PreviousLaudos $i)
        if ($prev.Count) { "     JÁ PASSOU POR AQUI - último laudo: " + @(Format-PreviousLaudos $prev 1)[-1] }
    }
    $msg = "Diagnóstico completo em:`r`n$($lines -join "`r`n")`r`n`r`n" +
           "Etapas: análise SMART -> autoteste do próprio disco (~2 min) -> leitura de 2.000 pontos do disco -> laudo em PDF.`r`n" +
           "Leva poucos minutos e NÃO altera nenhum dado."
    if ($busy.Count) { $msg += "`r`n`r`nIgnorado(s), em uso: " + (($busy | ForEach-Object { "Disco $($_.Number)" }) -join ', ') }
    if ($tbCliente.Text.Trim() -or $tbOS.Text.Trim()) { $msg += "`r`nCliente/OS do laudo: $($tbCliente.Text.Trim()) $($tbOS.Text.Trim())" }
    else { $msg += "`r`n`r`nDica: preencha Cliente e Nº OS (no quadro abaixo) antes, para saírem no laudo." }
    if ((Show-Msg $msg 'Question' 'YesNo') -ne 'Yes') { return }
    Start-DiagnosticOps $sel
}

function Start-DiagnosticOps($sel) {
    $new = @(foreach ($i in $sel) {
        $skip = $null
        if (-not $SmartctlPath) { $skip = 'smartctl não encontrado' }
        elseif (-not $i.SmartDevArgs) {
            $skip = 'o disco/adaptador não dá acesso ao autoteste (comum em gavetas USB)'
            if ($RstController -and $i.Bus -in 'NVMe', 'RAID', 'SATA') { $skip = 'bloqueado pelo controlador Intel RST/VMD' }
        }
        $stages = @('sample'); if (-not $skip) { $stages = @('selftest', 'sample') }
        New-Op $i 'diag' 'diag' $stages @{ SelfTestSkip = $skip; Cliente = $tbCliente.Text.Trim(); OS = $tbOS.Text.Trim() }
    })
    Start-Ops $new
}
$btnDiag.Add_Click({ Start-Diagnostics })
$tipDiag = New-Object Windows.Forms.ToolTip
$tipDiag.SetToolTip($btnDiag, 'Um clique: análise SMART + autoteste curto + teste rápido de leitura e, no final, o laudo técnico em PDF. Não altera dados.')

$btnFull.Add_Click({ Start-ReadTests 'read' })
$btnSample.Add_Click({ Start-ReadTests 'sample' })

$btnExport.Add_Click({ $cmsRep.Show($btnExport, (New-Object Drawing.Point(0, $btnExport.Height))) })
$miLaudo.Add_Click({
    $sel = @(Get-SelectedDisks); if (-not $sel.Count) { return }
    $form.Cursor = 'WaitCursor'
    $made = @()
    try {
        foreach ($i in $sel) {
            $tests = @($script:Ops | Where-Object {
                -not $_.Active -and $_.Info.Serial -eq $i.Serial -and $_.Info.Size -eq $i.Size -and
                $_.Kind -in 'test', 'selftest', 'bench', 'capacity', 'repair', 'diag' } | Sort-Object StartTime)
            $made += New-DiskLaudo $i $tbCliente.Text.Trim() $tbOS.Text.Trim() $tests
        }
    } catch {
        Write-Log "Erro ao gerar laudo: $($_.Exception.Message)"
        Show-Msg "Erro ao gerar o laudo: $($_.Exception.Message)" 'Error' | Out-Null
    } finally { $form.Cursor = 'Default' }
    if ($made.Count -and (Show-Msg ("Laudo(s) salvo(s) na pasta Laudos:`r`n" + (($made | ForEach-Object { [IO.Path]::GetFileName($_) }) -join "`r`n") + "`r`n`r`nAbrir agora?") 'Information' 'YesNo') -eq 'Yes') {
        foreach ($m in $made) { Start-Process $m }
    }
})

$miLaudos.Add_Click({
    $d = Join-Path $ScriptDir 'Laudos'
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
    Start-Process explorer.exe $d
})

$miLaudoCsv.Add_Click({
    if (Test-Path $LaudoCsv) { Start-Process $LaudoCsv }
    else { Show-Msg 'Ainda não há laudos registrados. O registro é criado ao gerar o primeiro laudo (Diagnóstico completo ou Relatórios > Laudo técnico).' | Out-Null }
})

$miExport.Add_Click({
    $dlg = New-Object Windows.Forms.SaveFileDialog
    $dlg.Filter = 'Texto (*.txt)|*.txt'
    $dlg.FileName = 'Relatorio_Discos_{0:yyyyMMdd_HHmm}_{1}.txt' -f (Get-Date), $env:COMPUTERNAME
    if ($dlg.ShowDialog($form) -ne 'OK') { return }
    $form.Cursor = 'WaitCursor'
    $txt = "Relatório de discos - $env:COMPUTERNAME - $(Get-Date -Format 'dd/MM/yyyy HH:mm')`r`n`r`n"
    foreach ($i in $script:Disks) { $txt += (Get-HealthReport $i -WithSmartctl) + "`r`n`r`n" + (Get-HistoryText $i) + "`r`n`r`n" }
    [IO.File]::WriteAllText($dlg.FileName, $txt, (New-Object Text.UTF8Encoding($true)))
    $form.Cursor = 'Default'
    Write-Log "Relatório salvo em $($dlg.FileName)"
})

$btnCancel.Add_Click({
    if (-not $lvOps.SelectedItems.Count) { Show-Msg 'Selecione uma operação na lista de operações.' 'Warning' | Out-Null; return }
    $op = $lvOps.SelectedItems[0].Tag
    if (-not $op.Active) { return }
    if ((Show-Msg "Cancelar a operação no disco $($op.Info.Number)?" 'Question' 'YesNo') -ne 'Yes') { return }
    if ($op.Job) {
        if ($op.Job.Mode -eq 'erase') { Show-Msg 'O apagamento pelo controlador não pode ser interrompido; aguarde terminar.' 'Warning' | Out-Null; return }
        $op.Job.Cancel = $true
    }
    if ($op.SelfTest) { $op.SelfTest.CancelReq = $true }
})

$btnCerts.Add_Click({
    if (-not (Test-Path $CertDir)) { New-Item -ItemType Directory -Path $CertDir | Out-Null }
    Start-Process explorer.exe $CertDir
})

$btnClearOps.Add_Click({
    foreach ($op in @($script:Ops | Where-Object { -not $_.Active })) {
        $lvOps.Items.Remove($op.Item); [void]$script:Ops.Remove($op)
        if ($script:ChartOp -eq $op) { $script:ChartOp = $null }
    }
    $pic.Invalidate()
})

# ----- Autoteste SMART
function Start-SelfTests([string]$method) {
    if (-not $SmartctlPath) { Show-Msg 'O autoteste precisa do smartctl.exe (smartmontools) na pasta do DiskTool.' 'Warning' | Out-Null; return }
    $sel = @(Get-SelectedDisks); if (-not $sel.Count) { return }
    $ok = @(); $skip = @()
    foreach ($i in $sel) {
        if (Test-DiskBusy $i.Number) { $skip += "Disco $($i.Number): já está em uso por outra operação" }
        elseif ($i.Size -le 0) { $skip += "Disco $($i.Number): informa 0 bytes (sem mídia ou com defeito)" }
        elseif (-not $i.SmartDevArgs) {
            $why = 'comum em gavetas USB'
            if ($RstController -and $i.Bus -in 'NVMe', 'RAID', 'SATA') { $why = "bloqueado pelo controlador Intel RST/VMD" }
            $skip += "Disco $($i.Number): o smartctl não consegue acessar este disco ($why)"
        }
        else { $ok += $i }
    }
    if ($skip.Count) { Show-Msg ("Não será testado:`r`n" + ($skip -join "`r`n")) 'Warning' | Out-Null }
    if (-not $ok.Count) { return }
    $dur = 'O teste curto leva cerca de 2 minutos.'
    if ($method -eq 'selftest_long') { $dur = 'O teste longo varre toda a superfície e pode levar várias horas em HDD (minutos em NVMe).' }
    $names = ($ok | ForEach-Object { "Disco $($_.Number) - $($_.Model)" }) -join "`r`n"
    $r = Show-Msg ("O próprio disco vai executar o autoteste de fábrica em:`r`n$names`r`n`r`n$dur`r`n" +
                   "O teste NÃO apaga dados e o PC pode continuar em uso. O resultado é o aceito pelos fabricantes para garantia.") 'Question' 'YesNo'
    if ($r -ne 'Yes') { return }
    $new = @(foreach ($i in $ok) { New-Op $i 'selftest' $method @('selftest') $null })
    Start-Ops $new
}
$btnSelf.Add_Click({ $cmsSelf.Show($btnSelf, (New-Object Drawing.Point(0, $btnSelf.Height))) })
$miShort.Add_Click({ Start-SelfTests 'selftest_short' })
$miLong.Add_Click({ Start-SelfTests 'selftest_long' })

# ----- Benchmark (não destrutivo: arquivo temporário apagado automaticamente)
function Start-Benchmark {
    $sel = @(Get-SelectedDisks); if (-not $sel.Count) { return }
    if ($sel.Count -gt 1) { Show-Msg 'O benchmark é feito em um disco por vez (vários ao mesmo tempo distorcem o resultado). Selecione só um.' 'Warning' | Out-Null; return }
    $i = $sel[0]
    if (-not (Test-DisksHaveMedia @($i))) { return }
    if (Test-DiskBusy $i.Number) { Show-Msg "O disco $($i.Number) já está em uso por outra operação." 'Warning' | Out-Null; return }
    $sizeMB = 1024
    $vols = @(Get-Partition -DiskNumber $i.Number -ErrorAction SilentlyContinue |
              Where-Object { "$($_.DriveLetter)" -match '[A-Z]' } |
              ForEach-Object { Get-Volume -DriveLetter $_.DriveLetter -ErrorAction SilentlyContinue } |
              Where-Object { $_ -and $_.SizeRemaining -gt ($sizeMB * 1MB + 512MB) } |
              Sort-Object SizeRemaining -Descending)
    if (-not $vols.Count) {
        Show-Msg ("O benchmark precisa de uma unidade com letra e pelo menos 1,5 GB livre neste disco.`r`n" +
                  'Se o disco está vazio, formate-o primeiro (modo Rápido).') 'Warning' | Out-Null
        return
    }
    $letter = "$($vols[0].DriveLetter)"
    $r = Show-Msg ("Benchmark do disco $($i.Number) ($($i.Model)) na unidade $($letter):`r`n`r`n" +
                   "Grava e lê um arquivo temporário de 1 GB (apagado ao final) e mede:`r`n" +
                   "- leitura e gravação sequencial (arquivos grandes)`r`n- leitura e gravação aleatória 4K (sistema, programas)`r`n`r`n" +
                   "Leva cerca de 1 minuto. Os dados do disco NÃO são alterados. Feche programas que usam o disco para um resultado mais fiel.") 'Question' 'YesNo'
    if ($r -ne 'Yes') { return }
    Start-Ops @(New-Op $i 'bench' 'bench' @('bench') @{ Path = "$($letter):\"; SizeMB = $sizeMB })
}
$miBench.Add_Click({ Start-Benchmark })

# ----- Teste de capacidade real (detecta pendrive/cartão com capacidade falsificada)
$miFake.Add_Click({
    $sel = @(Get-SelectedDisks); if (-not $sel.Count) { return }
    if (-not (Test-DisksHaveMedia $sel)) { return }
    foreach ($i in $sel) {
        if ($i.Protected) { Show-Msg "O disco $($i.Number) está protegido:`r`n$($i.Protected)" 'Stop' | Out-Null; return }
        if (Test-DiskBusy $i.Number) { Show-Msg "O disco $($i.Number) já está em uso por outra operação." 'Warning' | Out-Null; return }
        if (-not (Test-SameDisk $i)) { Show-Msg 'Os discos mudaram desde a última leitura. Atualize a lista e selecione de novo.' 'Warning' | Out-Null; Update-DiskList; return }
    }
    $fs = [string]$cbFs.SelectedItem
    if ($chkFormat.Checked -and $fs -eq 'FAT32' -and @($sel | Where-Object { $_.Size -gt 32GB }).Count) {
        Show-Msg 'O Windows só formata em FAT32 partições de até 32 GB. Use exFAT ou NTFS.' 'Warning' | Out-Null; return
    }
    $head = "TODOS OS DADOS dos discos abaixo serão destruídos.`r`n`r`n" +
            'O teste grava 4.096 blocos assinados espalhados por toda a capacidade anunciada e depois relê todos. ' +
            'Pendrives e cartões falsificados "dão a volta": o que é gravado no fim sobrescreve o começo, e o teste mostra a capacidade real. ' +
            'Leva de segundos a poucos minutos.'
    if ($chkFormat.Checked) { $head += "`r`nSe a capacidade conferir, o disco é formatado em $fs no final." }
    if (-not (Show-ConfirmWipe $sel 'Teste de capacidade real' 'APAGAR' $head 'Testar')) { return }
    $opts = @{ Style = [string]$cbStyle.SelectedItem; Fs = $fs; Label = $tbLabel.Text.Trim() }
    $new = @(foreach ($i in $sel) {
        $stages = @('clear', 'fakecheck'); if ($chkFormat.Checked) { $stages += 'format' }
        New-Op $i 'capacity' 'fakecheck' $stages $opts
    })
    Start-Ops $new
})

# ----- Configurações do certificado
$btnConfig.Add_Click({
    $f = New-Object Windows.Forms.Form
    $f.SuspendLayout()
    $f.AutoScaleDimensions = New-Object Drawing.SizeF(96, 96); $f.AutoScaleMode = 'Dpi'
    $f.Text = 'Configurações'; $f.ClientSize = New-Object Drawing.Size(540, 390)
    $f.FormBorderStyle = 'FixedDialog'; $f.StartPosition = 'CenterParent'; $f.MaximizeBox = $false; $f.MinimizeBox = $false
    $f.Font = $fontUI
    $fields = @{}
    $y = 18
    foreach ($def in @(@('Empresa', 'Nome da empresa:'), @('Contato', 'CNPJ / telefone / e-mail:'), @('Tecnico', 'Técnico responsável:'), @('Logo', 'Logo (PNG ou JPG):'))) {
        $l = New-Object Windows.Forms.Label; $l.Text = $def[1]; $l.AutoSize = $true; $l.Location = New-Object Drawing.Point(15, ($y + 3))
        $t = New-Object Windows.Forms.TextBox; $t.Location = New-Object Drawing.Point(170, $y); $t.Width = 350; $t.Text = $Settings.($def[0])
        if ($def[0] -eq 'Logo') { $t.Width = 260 }
        $f.Controls.AddRange(@($l, $t)); $fields[$def[0]] = $t
        $y += 40
    }
    $tbLogo = $fields['Logo']
    $browse = New-Object Windows.Forms.Button; $browse.Text = 'Procurar...'; $browse.Location = New-Object Drawing.Point(440, 136); $browse.Size = New-Object Drawing.Size(80, 26)
    $browse.Add_Click({
        $d = New-Object Windows.Forms.OpenFileDialog
        $d.Filter = 'Imagens (*.png;*.jpg;*.jpeg;*.gif;*.bmp)|*.png;*.jpg;*.jpeg;*.gif;*.bmp'
        if ($d.ShowDialog() -eq 'OK') { $tbLogo.Text = $d.FileName }
    }.GetNewClosure())
    $hint = New-Object Windows.Forms.Label
    $hint.Text = 'Esses dados aparecem no cabeçalho de todos os certificados. Cliente e Nº da OS são preenchidos a cada apagamento, na tela principal.'
    $hint.Location = New-Object Drawing.Point(15, 172); $hint.Size = New-Object Drawing.Size(505, 34); $hint.ForeColor = 'DimGray'
    $lblTheme = New-Object Windows.Forms.Label; $lblTheme.Text = 'Tema:'; $lblTheme.AutoSize = $true; $lblTheme.Location = New-Object Drawing.Point(15, 335)
    $cbTheme = New-Object Windows.Forms.ComboBox; $cbTheme.DropDownStyle = 'DropDownList'; $cbTheme.Location = New-Object Drawing.Point(62, 331); $cbTheme.Width = 160
    [void]$cbTheme.Items.AddRange(@('Seguir o Windows', 'Claro', 'Escuro'))
    $cbTheme.SelectedIndex = @{ 'Sistema' = 0; 'Claro' = 1; 'Escuro' = 2 }[[string]$Settings.Theme]; if ($cbTheme.SelectedIndex -lt 0) { $cbTheme.SelectedIndex = 0 }
    $f.Controls.AddRange(@($lblTheme, $cbTheme))
    $chkMon = New-Object Windows.Forms.CheckBox
    $chkMon.Text = 'Monitor automático: verificar os discos todo dia às'; $chkMon.AutoSize = $true
    $chkMon.Location = New-Object Drawing.Point(15, 222); $chkMon.Checked = [bool](Get-MonitorTask)
    $dtMon = New-Object Windows.Forms.DateTimePicker
    $dtMon.Format = 'Custom'; $dtMon.CustomFormat = 'HH:mm'; $dtMon.ShowUpDown = $true; $dtMon.Width = 70
    $dtMon.Location = New-Object Drawing.Point(330, 219)
    try { $dtMon.Value = [datetime]::ParseExact($Settings.MonitorTime, 'HH:mm', $null) } catch { }
    $monHint = New-Object Windows.Forms.Label
    $monHint.Text = 'Cria uma tarefa agendada do Windows. Se algum disco piorar ou ficar crítico, aparece um aviso na tela. O PC precisa estar ligado (se estiver desligado, roda ao ligar).'
    $monHint.Location = New-Object Drawing.Point(33, 246); $monHint.Size = New-Object Drawing.Size(487, 44); $monHint.ForeColor = 'DimGray'
    $f.Controls.AddRange(@($chkMon, $dtMon, $monHint))
    $ok = New-Object Windows.Forms.Button; $ok.Text = 'Salvar'; $ok.DialogResult = 'OK'
    $ok.Location = New-Object Drawing.Point(320, 345); $ok.Size = New-Object Drawing.Size(95, 32)
    $cancel = New-Object Windows.Forms.Button; $cancel.Text = 'Cancelar'; $cancel.DialogResult = 'Cancel'
    $cancel.Location = New-Object Drawing.Point(425, 345); $cancel.Size = New-Object Drawing.Size(95, 32)
    $f.Controls.AddRange(@($browse, $hint, $ok, $cancel))
    $f.AcceptButton = $ok; $f.CancelButton = $cancel
    $f.ResumeLayout($false)
    $f.Add_Load({ param($s, $e) Set-Theme $s })
    if ($f.ShowDialog($form) -ne 'OK') { return }
    foreach ($k in 'Empresa', 'Contato', 'Tecnico', 'Logo') { $Settings.$k = $fields[$k].Text.Trim() }
    $newTheme = @('Sistema', 'Claro', 'Escuro')[$cbTheme.SelectedIndex]
    if ($newTheme -ne $Settings.Theme) {
        $Settings.Theme = $newTheme
        Set-ThemePalette (Get-ThemeIsDark); Set-Theme $form; Update-OpRowColors; Update-DiskList; $pic.Invalidate()
        Write-Log "Tema alterado para: $newTheme"
    }
    $Settings.MonitorTime = $dtMon.Value.ToString('HH:mm')
    if ($Settings.Logo -and -not (Test-Path $Settings.Logo)) { Show-Msg 'O arquivo do logo não foi encontrado; o certificado sairá sem logo.' 'Warning' | Out-Null }
    $hadTask = [bool](Get-MonitorTask)
    if ($chkMon.Checked -or $hadTask) {
        try {
            Set-MonitorTask $chkMon.Checked $Settings.MonitorTime
            if ($chkMon.Checked) { Write-Log "Monitor automático ativado: todo dia às $($Settings.MonitorTime)." }
            else { Write-Log 'Monitor automático desativado (tarefa agendada removida).' }
        } catch { Show-Msg "Não foi possível configurar o monitor automático: $($_.Exception.Message)" 'Error' | Out-Null }
    }
    try { Save-Settings $Settings; Write-Log 'Configurações salvas.' }
    catch { Show-Msg "Não foi possível salvar as configurações: $($_.Exception.Message)" 'Error' | Out-Null }
})

# ----- Reparo de setores ilegíveis (HDD)
$btnRepair.Add_Click({
    $how = 'Selecione na lista de operações um teste de leitura concluído (completo ou rápido) que encontrou blocos ilegíveis.'
    if (-not $lvOps.SelectedItems.Count) { Show-Msg $how 'Warning' | Out-Null; return }
    $src = $lvOps.SelectedItems[0].Tag
    if ($src.Kind -ne 'test' -or $src.Active) { Show-Msg $how 'Warning' | Out-Null; return }
    $r = $src.Results[$src.Method]
    if (-not $r -or -not @($r.Offsets).Count) { Show-Msg 'Esse teste não encontrou blocos ilegíveis - não há o que reparar.' | Out-Null; return }
    $i = @($script:Disks | Where-Object { $_.Number -eq $src.Info.Number -and $_.Serial -eq $src.Info.Serial })[0]
    if (-not $i) { Show-Msg 'Esse disco não está mais na lista. Clique em Atualizar lista e refaça o teste.' 'Warning' | Out-Null; return }
    if ($i.Tipo -ne 'HDD') {
        Show-Msg ('O reparo de setores é para HDD. SSD e NVMe substituem blocos ruins sozinhos; ' +
                  'se um SSD tem blocos ilegíveis, faça backup e substitua o disco.') 'Warning' | Out-Null
        return
    }
    if ($i.Protected) { Show-Msg "O disco $($i.Number) está protegido:`r`n$($i.Protected)`r`nRepare-o a partir de outro Windows ou de um pendrive de boot." 'Stop' | Out-Null; return }
    if (Test-DiskBusy $i.Number) { Show-Msg "O disco $($i.Number) já está em uso por outra operação." 'Warning' | Out-Null; return }
    if (-not (Test-SameDisk $i)) { Show-Msg 'O disco mudou desde a última leitura. Atualize a lista e refaça o teste.' 'Warning' | Out-Null; return }

    $letters = @(Get-Partition -DiskNumber $i.Number -ErrorAction SilentlyContinue |
                 Where-Object { "$($_.DriveLetter)" -match '[A-Z]' } | ForEach-Object { "$($_.DriveLetter)" })
    $n = @($r.Offsets).Count
    $lettersText = 'nenhuma'; if ($letters.Count) { $lettersText = ($letters | ForEach-Object { "$($_):" }) -join ' ' }
    $chk = 'X:'; if ($letters.Count) { $chk = "$($letters[0]):" }
    $extra = ''; if ($r.Errors -gt $n) { $extra = "`r`n(O teste achou $($r.Errors) blocos; serão tratados os primeiros $n.)" }
    $head = "O reparo grava zeros SOMENTE nos setores que não podem ser lidos, dentro de $n bloco(s) de 1 MB. " +
            "O conteúdo desses setores já está perdido; o resto do disco não é alterado.$extra`r`n`r`n" +
            "- Unidades deste disco ($lettersText) ficam indisponíveis durante o reparo: feche programas e janelas que as usam.`r`n" +
            "- Arquivos que usavam esses setores ficarão com trechos zerados. Depois rode:  chkdsk $chk /f`r`n" +
            "- Se o disco continuar criando setores ruins, faça backup e substitua-o."
    if (-not (Show-ConfirmWipe @($i) 'Reparo de setores ilegíveis' 'REPARAR' $head 'Reparar')) { return }
    $opts = @{ Blocks = @($r.Offsets); Letters = $letters; SectorSize = [Math]::Max(512, [int]$i.PhysicalSector) }
    Start-Ops @(New-Op $i 'repair' 'repair' @('repair') $opts)
})

$btnWipe.Add_Click({
    $sel = @(Get-SelectedDisks); if (-not $sel.Count) { return }
    foreach ($i in $sel) {
        if (-not (Test-DisksHaveMedia @($i))) { return }
        if ($i.Protected) { Show-Msg "O disco $($i.Number) está protegido e não pode ser apagado por aqui:`r`n$($i.Protected)" 'Stop' | Out-Null; return }
        if (Test-DiskBusy $i.Number) { Show-Msg "O disco $($i.Number) já está em uso por outra operação." 'Warning' | Out-Null; return }
        if (-not (Test-SameDisk $i)) {
            Show-Msg 'Os discos mudaram desde a última leitura. A lista será atualizada; selecione os discos novamente.' 'Warning' | Out-Null
            Update-DiskList; return
        }
    }
    $fs = [string]$cbFs.SelectedItem
    if ($chkFormat.Checked -and $fs -eq 'FAT32' -and @($sel | Where-Object { $_.Size -gt 32GB }).Count) {
        Show-Msg 'O Windows só formata em FAT32 partições de até 32 GB. Use exFAT ou NTFS.' 'Warning' | Out-Null
        return
    }
    $method = 'quick'
    if ($rbZero.Checked) { $method = 'zero' }
    if ($rbSecure.Checked) { $method = 'secure' }

    $flash = @($sel | Where-Object { $_.Tipo -in 'SSD', 'NVMe' })
    if ($method -eq 'zero' -and $flash.Count) {
        $r = Show-Msg ("Há SSD/NVMe na seleção. Zerar SSD gasta ciclos de escrita e, por causa do wear-leveling, " +
                       "não garante apagar 100% das células.`r`n`r`nPara SSD/NVMe prefira 'Apagamento seguro pelo controlador'.`r`n`r`nContinuar com a zeragem completa?") 'Warning' 'YesNo'
        if ($r -ne 'Yes') { return }
    }
    if ($method -eq 'secure') {
        $hdd = @($sel | Where-Object { $_.Tipo -eq 'HDD' })
        if ($hdd.Count) { Show-Msg 'O apagamento pelo controlador é para SSD/NVMe. Para HDD use o modo Completo.' 'Warning' | Out-Null; return }
        $r = Show-Msg ("O apagamento pelo controlador é EXPERIMENTAL: nem todo disco/driver aceita o comando. " +
                       "Se não for aceito, nada é apagado além das partições e o programa avisa.`r`n`r`nContinuar?") 'Warning' 'YesNo'
        if ($r -ne 'Yes') { return }
    }
    $modeText = @{ quick = 'Rápido (apagar partições + formatar)'; zero = 'Completo (sobrescrever com zeros)'; secure = 'Apagamento seguro pelo controlador' }[$method]
    if (-not (Show-ConfirmWipe $sel $modeText)) { Write-Log 'Operação cancelada na confirmação.'; return }

    $opts = @{ Style = [string]$cbStyle.SelectedItem; Fs = $fs; Label = $tbLabel.Text.Trim()
               Cliente = $tbCliente.Text.Trim(); OS = $tbOS.Text.Trim() }
    $new = @()
    foreach ($i in $sel) {
        $stages = @('clear')
        if ($method -eq 'zero')   { $stages += 'zero';  if ($chkVerify.Checked) { $stages += 'verify' } }
        if ($method -eq 'secure') { $stages += 'erase'; if ($chkVerify.Checked) { $stages += 'verifysample' } }
        if ($chkFormat.Checked) { $stages += 'format' }
        if ($chkCert.Checked) { $stages += 'cert' }
        $new += New-Op $i 'wipe' $method $stages $opts
    }
    Start-Ops $new
})

$form.Add_FormClosing({
    param($s, $e)
    $active = @(Get-ActiveOps)
    if ($active.Count) {
        if ((Show-Msg "Há $($active.Count) operação(ões) em andamento. Cancelar e sair?" 'Warning' 'YesNo') -ne 'Yes') { $e.Cancel = $true; return }
        foreach ($op in $active) { if ($op.Job) { $op.Job.Cancel = $true } }
        foreach ($op in $active) { if ($op.Job) { while ($op.Job.Running) { Start-Sleep -Milliseconds 100 } } }
    }
})

$form.Add_Load({ Set-Theme $form })
$form.Add_Shown({
    Write-Log "DiskTool $AppVersion iniciado."
    if ($SmartctlPath) { $lblSmart.Text = 'smartctl: ativo'; $lblSmart.ForeColor = 'ForestGreen' }
    else { $lblSmart.Text = 'smartctl: não encontrado'; $lblSmart.ForeColor = 'DarkOrange' }
    $tip = New-Object Windows.Forms.ToolTip
    $tip.SetToolTip($lblSmart, $(if ($SmartctlPath) { $SmartctlPath } else { 'Sem o smartctl os dados SMART ficam limitados.' }))
    Update-DiskList
    # Atualização automática quando um disco/pendrive é conectado ou removido
    try {
        $script:Watcher = New-Object DeviceWatcher
        $script:Watcher.AssignHandle($form.Handle)
        $script:SeenChanges = [DeviceWatcher]::Changes
        $devTimer.Start()
    } catch { Write-Log "Detecção automática de discos indisponível: $($_.Exception.Message)" }
})

$devTimer = New-Object Windows.Forms.Timer
$devTimer.Interval = 1500
$script:ChangeAt = $null
$devTimer.Add_Tick({
    $c = [DeviceWatcher]::Changes
    if ($c -ne $script:SeenChanges) { $script:SeenChanges = $c; $script:ChangeAt = Get-Date; return }   # espera estabilizar
    if (-not $script:ChangeAt -or ((Get-Date) - $script:ChangeAt).TotalSeconds -lt 2) { return }
    if ($script:InTick -or $script:InDiskList) { return }
    # Fora do modo bancada, durante operações a lista só é atualizada ao final
    if (-not $chkBench.Checked -and @(Get-ActiveOps).Count) { return }
    $script:ChangeAt = $null
    # O Windows avisa sobre qualquer aparelho (mouse, celular, fone...): só relê se a lista de discos mudou.
    $sig = Get-DiskSetSignature
    if ($null -eq $sig -or $sig -eq $script:DiskSetSig) { return }
    $before = @($script:Disks | ForEach-Object { Get-BenchKey $_ })
    Write-Log 'Disco conectado/removido - atualizando a lista.'
    Update-DiskList
    if ($chkBench.Checked) { Start-BenchAuto $before }
})

# ----- Modo bancada: diagnóstico automático de discos recém-conectados
function Get-BenchKey($i) { "$(if ($i.Serial) { $i.Serial } else { $i.Model })|$($i.Size)" }

function Start-BenchAuto($before) {
    $new = @($script:Disks | Where-Object { $before -notcontains (Get-BenchKey $_) })
    $go = @()
    foreach ($i in $new) {
        if ($i.Size -le 0) { Write-Log "Modo bancada: disco $($i.Number) ($($i.Model)) sem mídia - ignorado."; continue }
        if ($i.Protected) { Write-Log "Modo bancada: disco $($i.Number) ($($i.Model)) é protegido ($($i.Protected)) - ignorado."; continue }
        if (Test-DiskBusy $i.Number) { continue }
        $prev = @(Get-PreviousLaudos $i)
        if ($prev.Count) { Write-Log "Modo bancada: disco $($i.Number) ($($i.Model)) JÁ PASSOU POR AQUI - último laudo: $(@(Format-PreviousLaudos $prev 1)[-1])" }
        $go += $i
    }
    if (-not $go.Count) { return }
    Write-Log ("Modo bancada: diagnóstico automático em " + (($go | ForEach-Object { "disco $($_.Number) ($($_.Model))" }) -join ', ') + '.')
    Start-DiagnosticOps $go
    $lblStatus.Text = "Modo bancada: diagnosticando $(($go | ForEach-Object { "disco $($_.Number)" }) -join ', ')..."
}

$chkBench.Add_CheckedChanged({
    $Settings.Bancada = $chkBench.Checked
    try { Save-Settings $Settings } catch { }
    Write-Log $(if ($chkBench.Checked) { 'Modo bancada ATIVADO: discos conectados a partir de agora serão diagnosticados automaticamente.' } else { 'Modo bancada desativado.' })
})
$form.ResumeLayout($false)
[void]$form.ShowDialog()
