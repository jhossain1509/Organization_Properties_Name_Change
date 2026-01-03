import asyncio, csv, time, struct, hmac, base64, hashlib, threading, datetime, sys, subprocess
from dataclasses import dataclass
from tkinter import *
from tkinter.filedialog import askopenfilename
from tkinter import messagebox
from queue import Queue, Empty
from playwright.async_api import async_playwright
import os

# --- Auto-install Playwright browsers on first run ---
def ensure_playwright_browsers():
    """Check and install playwright browsers if not found"""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            # Try to get browser, if fails then install
            try:
                p.chromium.executable_path
            except Exception:
                print("Installing Playwright browsers... Please wait...")
                subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=True)
                print("Playwright browsers installed successfully!")
    except Exception as e:
        print(f"Warning: Could not verify/install Playwright browsers: {e}")

# --- TOTP Generator ---
def totp(secret, interval=30):
    secret = secret.replace(" ", "").upper()
    key = base64.b32decode(secret + "="*((8-len(secret)%8)%8))
    msg = struct.pack(">Q", int(time.time()) // interval)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return f"{code:06d}"

# ---------------------- Playwright Runner ----------------------
class PWRunner:
    """Dedicated background thread with persistent playwright instance"""
    def __init__(self, app):
        self.app = app
        self.loop = None
        self.thread = None
        self.playwright = None
        self.chromium = None
        self.browsers = []
        self.is_running = False

    def start(self):
        """Start the background thread and event loop"""
        if self.thread and self.thread.is_alive():
            return
        self.is_running = True
        self.thread = threading.Thread(target=self._loop_thread_main, daemon=True)
        self.thread.start()

    def _loop_thread_main(self):
        """Main loop for the background thread"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._async_init())
        self.loop.run_forever()

    async def _async_init(self):
        """Initialize playwright instance"""
        self.playwright = await async_playwright().start()
        self.chromium = self.playwright.chromium
        self.app.safe_log("✅ Playwright started!")

    def stop(self):
        """Stop playwright and close all browsers"""
        if not self.loop:
            return
        self.is_running = False
        async def _shutdown():
            try:
                for b in list(self.browsers):
                    try: await b.close()
                    except: pass
                if self.playwright:
                    await self.playwright.stop()
            finally:
                self.loop.stop()
        asyncio.run_coroutine_threadsafe(_shutdown(), self.loop)

    def login_account(self, acc):
        """Login single account - thread-safe"""
        if not self.loop:
            self.app.safe_log("⚠️ Playwright not started!")
            return
        asyncio.run_coroutine_threadsafe(self._login_one(acc), self.loop)

    def login_batch(self, accounts):
        """Login multiple accounts - thread-safe"""
        if not self.loop:
            self.app.safe_log("⚠️ Playwright not started!")
            return
        asyncio.run_coroutine_threadsafe(self._login_batch(accounts), self.loop)

    async def _login_batch(self, accounts):
        """Login multiple accounts in parallel"""
        await asyncio.gather(
            *[self._login_one(acc) for acc in accounts],
            return_exceptions=True
        )

    async def _login_one(self, acc):
        """Login one account"""
        try:
            acc.status = "Logging"
            self.app.update_csv_status(acc.email, "Logging")
            self.app.safe_log(f"🔐 {acc.email} → Logging in…")

            # Calculate window position
            browser_slot = len(self.browsers)
            win_w, win_h = self.app.win_width, self.app.win_height
            pos_x = 40 + (browser_slot % 5) * win_w
            pos_y = 80 + (browser_slot // 5) * win_h

            # Launch browser
            browser = await self.chromium.launch(
                headless=False,
                args=[
                    f"--window-size={win_w},{win_h}",
                    f"--window-position={pos_x},{pos_y}",
                    f"--remote-debugging-port={9222 + browser_slot}",
                ]
            )
            self.browsers.append(browser)
            ctx = await browser.new_context(viewport={"width": win_w, "height": win_h})
            page = await ctx.new_page()

            # Login flow
            await page.goto("https://entra.microsoft.com/", timeout=600000)
            
            await page.fill("input[name='loginfmt'],input[type='email']", acc.email)
            await page.click("#idSIButton9,button[type='submit'],input[type='submit']")
            
            await page.wait_for_selector("input[name='passwd'],input[type='password']", timeout=350000)
            await page.fill("input[name='passwd'],input[type='password']", acc.password)
            await page.click("#idSIButton9,button[type='submit'],input[type='submit']", timeout=350000)
            await asyncio.sleep(3)
            
            # Stay signed in?
            try:
                if await page.is_visible("#idSIButton9"):
                    await page.click("#idSIButton9")
                else:
                    yes_span = await page.query_selector('span:has-text("Yes")')
                    if yes_span:
                        await yes_span.evaluate('node => node.parentElement.click()')
            except: pass
            
            # 2fa Handling
            try:
                el = await self._wait_for_visible(page, 'input[type="tel"],input[name*="code"],input[autocomplete="one-time-code"]', 15)
                if el and acc.secret:
                    code = totp(acc.secret)
                    await el.fill(code)
                    await self._wait_and_click(page, "button[type='submit'],input[type='submit']", 10)
                    self.app.safe_log(f"✅ {acc.email} → OTP OK ({code})")
                    await asyncio.sleep(2.5)
            except: pass

            # Navigate to Properties page
            await page.wait_for_load_state('networkidle')
            await asyncio.sleep(3)
            
            self.app.safe_log(f"🔄 {acc.email} → Navigating to Properties page…")
            await page.goto(
                "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/TenantOverview.ReactView/initialValue//tabId//recommendationResourceId//fromNav/Identity",
                timeout=60000
            )
            await page.wait_for_load_state('networkidle')
            await asyncio.sleep(3)

            # Mark as Done
            acc.status = "Login Done"
            self.app.update_csv_status(acc.email, "Login Done")
            self.app.safe_log(f"✅ {acc.email} → LOGIN COMPLETE! (Browser will stay open)")

        except Exception as e:
            self.app.safe_log(f"❌ {acc.email} → FAILED: {e}")
            acc.status = "Failed"
            self.app.update_csv_status(acc.email, "Failed")

    async def _wait_for_visible(self, page, selectors, max_wait=30):
        """Helper: wait for visible element"""
        if isinstance(selectors, str):
            selectors = [selectors]
        end = time.time() + max_wait
        while time.time() < end:
            for sel in selectors:
                try:
                    el = await page.query_selector(sel)
                    if el and await el.is_visible():
                        return el
                except: pass
            await asyncio.sleep(0.5)
        return None

    async def _wait_and_click(self, page, selectors, max_wait=30):
        """Helper: wait and click"""
        if isinstance(selectors, str):
            selectors = [selectors]
        end = time.time() + max_wait
        while time.time() < end:
            for sel in selectors:
                try:
                    el = await page.query_selector(sel)
                    if el and await el.is_visible():
                        await el.click(timeout=3000)
                        return True
                except: pass
            await asyncio.sleep(0.5)
        raise Exception(f"Could not click {selectors}")

@dataclass
class Account:
    email: str
    password: str
    secret: str
    status: str = "Pending"  # Pending, Logging, Login Done, Failed

class EntraOrgRenameGUI:
    def __init__(self):
        self.root = Tk()
        self.root.title("GoldenIT • Entra Auto Login")
        self.root.geometry("950x650")
        self.root.configure(bg="#101820")

        self.status_q = Queue()
        self.win_width = 520
        self.win_height = 640
        self.accounts = []
        self.csv_path = ""

        # Initialize PWRunner
        self.runner = PWRunner(self)
        self.runner.start()

        # CSV Path
        Label(self.root, text="Accounts CSV (email,password,2fa_secret)", bg="#101820", fg="#ddd", font=("Arial",10)).place(x=20,y=20)
        self.acc_path = StringVar()
        Entry(self.root, textvariable=self.acc_path, width=60).place(x=20,y=50)
        Button(self.root, text="Browse", command=self.browse, bg="#3498db", fg="white").place(x=520,y=48)

        # Max Browsers
        Label(self.root, text="Max Browsers Open", bg="#101820", fg="#ddd", font=("Arial",10)).place(x=650,y=20)
        self.max_browsers = IntVar(value=2)
        Entry(self.root, textvariable=self.max_browsers, width=10).place(x=650,y=50)

        # Load CSV Button
        Button(self.root, text="LOAD CSV", bg="#9b59b6", fg="white",
               font=("Arial",11,"bold"), command=self.load_csv).place(x=750,y=48)

        # Start Button
        Button(self.root, text="START LOGIN", bg="#2ecc71", fg="white",
               font=("Arial",12,"bold"), command=self.start).place(x=20,y=100)
        
        # Login Next Account Button
        Button(self.root, text="Login Next Account", bg="#e74c3c", fg="white",
               font=("Arial",11,"bold"), command=self.login_next).place(x=180,y=101)
        
        # Stop Button
        Button(self.root, text="STOP", bg="#95a5a6", fg="white",
               font=("Arial",11,"bold"), command=self.stop).place(x=380,y=101)

        # Accounts Status Table
        Label(self.root, text="Accounts Status:", bg="#101820", fg="#ddd", font=("Arial",11,"bold")).place(x=20,y=150)
        
        self.acc_frame = Frame(self.root, bg="#0b1220")
        self.acc_frame.place(x=20, y=180, width=910, height=180)
        
        self.acc_text = Text(self.acc_frame, width=110, height=10, bg="#0b1220", fg="#eee", font=("Consolas",9))
        self.acc_text.pack(fill=BOTH, expand=True)

        # Logs
        Label(self.root, text="Activity Logs:", bg="#101820", fg="#ddd", font=("Arial",11,"bold")).place(x=20,y=380)
        self.log = Text(self.root, width=110, height=12, bg="#0b1220", fg="#eee", font=("Consolas",9))
        self.log.place(x=20,y=410)

        self.root.after(500, self.poll_log)
        self.root.after(1000, self.update_acc_table)

    def browse(self):
        p = askopenfilename(filetypes=[("CSV","*.csv")])
        if p: self.acc_path.set(p)

    def update_csv_status(self, email, new_status):
        """Update status in CSV file"""
        try:
            if not self.csv_path or not os.path.exists(self.csv_path):
                return
            
            rows = []
            with open(self.csv_path, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                fieldnames = reader.fieldnames
                
                # Add status column if not exists
                if fieldnames and 'status' not in fieldnames:
                    fieldnames = list(fieldnames) + ['status']
                elif not fieldnames:
                    fieldnames = ['email', 'password', '2fa_secret', 'status']
                
                for row in reader:
                    if row['email'] == email:
                        row['status'] = new_status
                    elif 'status' not in row:
                        row['status'] = ''
                    rows.append(row)
            
            # Write back to CSV
            with open(self.csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            
            self.status_q.put({"msg": f"📝 CSV Updated: {email} → {new_status}"})
        except Exception as e:
            self.status_q.put({"msg": f"⚠️ CSV Update Error: {e}"})

    def load_csv(self):
        if not self.acc_path.get():
            messagebox.showerror("Error","Please select CSV file")
            return

        self.accounts = []
        self.csv_path = self.acc_path.get()
        
        try:
            with open(self.csv_path, newline="", encoding="utf-8") as f:
                r = csv.DictReader(f)
                for row in r:
                    # Check if status column exists, if not default to Pending
                    status = row.get('status', '').strip()
                    # Treat blank/empty as Pending
                    if not status or status == '':
                        status = 'Pending'
                    
                    self.accounts.append(Account(
                        email=row["email"],
                        password=row["password"],
                        secret=row["2fa_secret"],
                        status=status
                    ))
            self.update_acc_table()
            self.logit(f"✅ Loaded {len(self.accounts)} accounts from CSV")
            
            # Count pending
            pending_count = len([a for a in self.accounts if a.status == "Pending"])
            self.logit(f"📊 Pending: {pending_count}, Completed: {len(self.accounts)-pending_count}")
            messagebox.showinfo("Success", f"Loaded {len(self.accounts)} accounts!\nPending: {pending_count}")
        except Exception as e:
            messagebox.showerror("Error", f"CSV read error: {e}")

    def update_acc_table(self):
        self.acc_text.delete(1.0, END)
        self.acc_text.insert(END, f"{'#':<4} {'email':<50} {'Status':<15}\n")
        self.acc_text.insert(END, "-"*110 + "\n")
        for idx, acc in enumerate(self.accounts):
            if acc.status == "Pending":
                status_icon = "⏳"
            elif acc.status == "Logging":
                status_icon = "🔄"
            elif acc.status == "Login Done":
                status_icon = "✅"
            elif acc.status == "Failed":
                status_icon = "❌"
            else:
                status_icon = "✅"
            
            self.acc_text.insert(END, f"{idx+1:<4} {acc.email:<50} {status_icon} {acc.status:<15}\n")
        self.root.after(2000, self.update_acc_table)

    def logit(self, msg):
        self.log.insert(END, f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}\n")
        self.log.see(END)

    def poll_log(self):
        try:
            while True:
                item = self.status_q.get_nowait()
                if isinstance(item, dict):
                    self.logit(item.get("msg", ""))
                else:
                    self.logit(item)
        except Empty:
            pass
        self.root.after(500, self.poll_log)

    def start(self):
        """Start login for max_browsers accounts"""
        if not self.accounts:
            messagebox.showerror("Error","Please load CSV first")
            return

        pending = [acc for acc in self.accounts if acc.status == "Pending" or acc.status == ""]
        if not pending:
            messagebox.showinfo("Info", "No pending accounts!")
            return

        max_to_login = min(self.max_browsers.get(), len(pending))
        batch = pending[:max_to_login]
        
        self.logit(f"🚀 Starting {len(batch)} browser(s)...")
        self.runner.login_batch(batch)
    
    def stop(self):
        """Stop all operations"""
        self.runner.stop()
        self.logit("🛑 Stopped! All operations halted.")
    
    def login_next(self):
        """Login next pending account"""
        if not self.accounts:
            messagebox.showerror("Error","Please load CSV first")
            return
        
        pending = [acc for acc in self.accounts if acc.status == "Pending" or acc.status == ""]
        if not pending:
            messagebox.showinfo("Info","No pending accounts!")
            return
        
        self.logit(f"🚀 Launching: {pending[0].email}")
        self.runner.login_account(pending[0])

    def safe_log(self, msg):
        """Thread-safe logging"""
        if threading.current_thread() is threading.main_thread():
            self.logit(msg)
        else:
            self.status_q.put({"msg": msg})

    def run(self):
        def on_close():
            try:
                self.runner.stop()
            except:
                pass
            self.root.destroy()
        self.root.protocol("WM_DELETE_WINDOW", on_close)
        self.root.mainloop()

if __name__ == "__main__":
    # Ensure playwright browsers are installed
    ensure_playwright_browsers()
    EntraOrgRenameGUI().run()
