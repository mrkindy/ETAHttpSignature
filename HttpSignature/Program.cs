using System;
using System.Windows.Forms;
using WebSocketSharp.Server;

namespace HttpSignature
{
    class Program
    {
        public static string ShowDialog(string caption, string text)
        {
            Form prompt = new Form()
            {
                Width = 355,
                Height = 160,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                Text = caption,
                StartPosition = FormStartPosition.CenterScreen,
                RightToLeftLayout = true,
                RightToLeft = RightToLeft.Yes,
                Icon = new System.Drawing.Icon("Resources/icon.ico")
            };

            Label textLabel = new Label() { Left = 40, Width = 250, Top = 20, Text = text };
            TextBox textBox = new TextBox() { Left = 40, Top = 50, Width = 250, PasswordChar = '*' };
            Button confirmation = new Button() { Text = "توقيع", Left = 190, Width = 100, Top = 85, DialogResult = DialogResult.OK };

            confirmation.Click += (sender, e) => { prompt.Close(); };
            prompt.Controls.Add(textBox);
            prompt.Controls.Add(confirmation);
            prompt.Controls.Add(textLabel);
            prompt.AcceptButton = confirmation;

            return prompt.ShowDialog() == DialogResult.OK ? textBox.Text : "";
        }

        public static void Main(string[] args)
        {
            var wssv = new WebSocketServer(18088);

            wssv.AddWebSocketService<Signature>("/");
            wssv.Start();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("█▓▒▒░░░Egyptian Tax E-Invoice HttpSignature Server░░░▒▒▓█");
            Console.WriteLine("Don't close this window or enter any key while you need to sign invoices from your system.");
            Console.WriteLine("Server Now Runing and wait conections to sign your invoices.");
            Console.ForegroundColor = ConsoleColor.White;
            Console.ReadKey();
            wssv.Stop();
        }
    }
}