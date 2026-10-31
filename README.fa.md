# RECON//NEXUS — ابزار متن‌باز OSINT و شناسایی امنیتی

[English README](README.md) · [نسخه وب](https://solohkemp-tech.github.io/recon-nexus/) · [کد در GitHub](https://github.com/solohkemp-tech/recon-nexus)

**RECON//NEXUS** یک مجموعه ابزار Python برای پژوهش OSINT، کشف زیردامنه و شناسایی امنیتی **در محدوده دارای مجوز** است. سه نسخه CLI، رابط گرافیکی Tkinter و محیط وب مبتنی بر GitHub Pages دارد.

CLI به پکیج اضافی pip یا کلید API نیاز ندارد؛ با این وجود، برخی ماژول‌ها به اینترنت و ارائه‌دهندگان داده عمومی درخواست می‌فرستند.

## قابلیت‌ها

- جست‌وجوی رکوردهای DNS و DNS-over-HTTPS
- بررسی متادیتای گواهی TLS و Subject Alternative Names
- کشف زیردامنه با Certificate Transparency و بررسی DNS
- تحلیل URLهای قدیمی در Wayback Machine
- ارزیابی اولیه هدرهای امنیتی HTTP
- بررسی اختیاری مسیرها بر روی سامانه‌های دارای مجوز
- کتابخانه جست‌وجوهای امنیتی و Dork برای موتورهای جست‌وجو
- ثبت گزارش در CLI و GUI

**هشدار:** وضعیت HTTP 200 یا 401، یا وجود مسیر ظاهراً حساس، به‌تنهایی آسیب‌پذیری را ثابت نمی‌کند. خروجی‌ها باید دستی تأیید شوند.

## نصب و شروع سریع

Python 3.8 یا جدیدتر لازم است. برای GUI به Tkinter و محیط دسکتاپ گرافیکی نیاز دارید؛ در برخی نسخه‌های Linux نصب بسته `python3-tk` ضروری است.

```bash
git clone https://github.com/solohkemp-tech/recon-nexus.git
cd recon-nexus
python cli/nexus.py --help
python cli/nexus.py dorks example.com
python cli/nexus.py dns example.com
```

روی سیستم‌هایی که دستور `python` ندارند از `python3` استفاده کنید. دستور `passive` هم ممکن است برای اطلاعات گواهی TLS با مقصد ارتباط برقرار کند؛ پس «بدون هرگونه تماس شبکه‌ای با مقصد» نیست.

### بررسی فعال، صرفاً در محدوده مجاز

```bash
python cli/nexus.py headers your-owned-domain.example
python cli/nexus.py probe your-owned-domain.example
python cli/nexus.py full your-owned-domain.example -o recon-report
```

این دستورات از کاربر تأیید مجوز می‌گیرند و در صورت درخواست، گزارش JSON تولید می‌کنند. صرف تأیید در برنامه جای مجوز واقعی مالک سامانه را نمی‌گیرد.

### نسخه دسکتاپ

```bash
python gui/nexus_gui.py
```

### نسخه وب

[اجرای Web Search Explorer](https://solohkemp-tech.github.io/recon-nexus/)

نسخه وب صرفاً برای ساخت و بازکردن جست‌وجوها در موتورهای جست‌وجو است و **اسکن DNS، TLS یا بررسی مسیر HTTP را در مرورگر اجرا نمی‌کند**.

## تفاوت سه نسخه

| نسخه | کاربرد |
|---|---|
| [CLI](cli/nexus.py) | اجرای ماژول‌ها از ترمینال و خروجی JSON |
| [GUI](gui/nexus_gui.py) | برنامه دسکتاپ Tkinter و خروجی گزارش |
| [Web](https://solohkemp-tech.github.io/recon-nexus/) | مرور و اجرای جست‌وجوهای عمومی |

## حریم خصوصی و گزارش باگ

استفاده از DNS، CT، آرشیوهای وب یا موتورهای جست‌وجو ممکن است داده مربوط به دامنه را نزد سرویس‌های ثالث ثبت کند. اطلاعات محرمانه، کلیدها و داده مشتریان را در Issue عمومی قرار ندهید.

برای گزارش خطا یا پیشنهاد توسعه از [GitHub Issues](https://github.com/solohkemp-tech/recon-nexus/issues) و برای مشکلات امنیتی از دستورالعمل [SECURITY.md](SECURITY.md) استفاده کنید.

اگر پروژه کاربردی است، می‌توانید با **Star** یا معرفی کاربرد واقعی آن از توسعه‌اش حمایت کنید.

**مجوز:** MIT · **توسعه‌دهنده:** [solohkemp-tech](https://github.com/solohkemp-tech)
