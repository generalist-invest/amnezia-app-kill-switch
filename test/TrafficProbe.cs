using System;
using System.Net;
using System.Windows.Forms;

namespace AmneziaKillSwitchTest
{
    internal sealed class ProbeForm : Form
    {
        private readonly Label status = new Label();
        private readonly Button probe = new Button();
        private const string TestUrl = "https://example.com/";

        public ProbeForm()
        {
            Text = "Traffic Probe — тест kill switch";
            Width = 540;
            Height = 225;
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;

            var info = new Label
            {
                Left = 20, Top = 18, Width = 485, Height = 55,
                Text = "Эта тестовая программа по кнопке делает один HTTPS-запрос к example.com.\r\nОна не запускает запросы сама и не передаёт никаких данных пользователя."
            };
            Controls.Add(info);

            probe.Left = 20;
            probe.Top = 90;
            probe.Width = 180;
            probe.Text = "Проверить соединение";
            probe.Click += Probe_Click;
            Controls.Add(probe);

            status.Left = 20;
            status.Top = 132;
            status.Width = 485;
            status.Height = 40;
            status.Text = "Статус: запрос ещё не выполнялся.";
            Controls.Add(status);
        }

        private async void Probe_Click(object sender, EventArgs e)
        {
            probe.Enabled = false;
            status.Text = "Статус: отправляю HTTPS-запрос…";
            try
            {
                await System.Threading.Tasks.Task.Run(() =>
                {
                    var request = WebRequest.Create(TestUrl);
                    request.Timeout = 8000;
                    request.Proxy = WebRequest.DefaultWebProxy;
                    using (var response = (HttpWebResponse)request.GetResponse())
                    {
                        if ((int)response.StatusCode < 200 || (int)response.StatusCode > 399)
                            throw new WebException("Сервер вернул HTTP " + (int)response.StatusCode);
                    }
                });
                status.Text = "Статус: УСПЕХ — HTTPS-соединение доступно.";
            }
            catch (Exception error)
            {
                status.Text = "Статус: ЗАБЛОКИРОВАНО / недоступно — " + error.GetType().Name;
            }
            finally
            {
                probe.Enabled = true;
            }
        }
    }

    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new ProbeForm());
        }
    }
}

