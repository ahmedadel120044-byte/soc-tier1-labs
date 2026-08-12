Splunk: Exploring SPL — SIEM & Log Analysis (TryHackMe Write-Up)

تقرير تحليلي وتوثيق عملي للتعامل مع لغة الاستعلامات SPL داخل منصة Splunk SIEM على منصة TryHackMe، لتجميع وتحليل السجلات الرقمية واكتشاف التهديدات.

📌 نبذة عن اللاب (Overview)
يركز اللاب على بناء المهارات الأساسية والمتقدمة في كتابة استعلامات البحث (SPL Queries) داخل منصة Splunk. يعتمد التحليل على فحص وتتبع أنواع مختلفة من الـ Logs (مثل Windows Security، Sysmon، و VPN Logs)، بداية من عمليات البحث المباشرة والفلترة الزمنية، مروراً بهيكلة وتجميع البيانات وربط المصادر المتعددة (Log Correlation)، وصولاً لاستخدام تقنيات كشف الشذوذ (Anomaly Detection) لرصد التهديدات والمحاولات المشبوهة.

🛠️ الأدوات المستخدمة (Tools Used)

Splunk Enterprise (SIEM Platform): المنصة الرئيسية لاستعلام وتحليل السجلات الرقمية.

SPL (Search Processing Language): لغة الاستعلامات لبناء الفلاتر، تحويل البيانات، واستخراج الإحصائيات.

Log Data Sources:

Sysmon Logs: لتتبع سلوك البرامج والعمليات (EventID=1).

Windows Security Logs: لتتبع أحداث تسجيل الدخول (EventID=4624).

VPN Logs (index=vpnlogs): لكشف الاتصالات المشبوهة والـ Outliers.

🔍 رحلة التحقيق والتحليل (Investigation Breakdown)

Search Operators & Filtering Basics

الهدف: تصفية السجلات وتنقية النتائج للوصول لأحداث محددة بفعالية دون استهلاك موارد النظام.

الأوامر والتقنيات:

استخدام المعاملات المنطقية: AND, OR, NOT.

تحديد الفترات الزمنية كودياً: earliest="04/15/2022:08:05:00" latest="04/15/2022:08:06:00".

تحسين الأداء وإخفاء الحقول الثقيلة: | fields - _raw.

ضبط الـ Event Sampling على No Event Sampling لضمان الحصول على العدد الدقيق الكامل للـ Events.

النتائج:

فهم أولوية المعاملات المنطقية واستخدام الأقواس لتحديد نطاق البحث.

التمييز بين التوقيت الفعلي للحدث (_time / EventTime) وتوقيت الـ Indexing داخل Splunk.

Structuring & Formatting Results

الهدف: تنظيم وتنسيق البيانات الناتجة في جداول واضحة وتغيير أسماء الحقول لعرض تقارير سهلة القراءة.

الأوامر والتقنيات:

ترتيب وتنظيم البيانات: | table User, EventID, SourceIp | rename SourceIp as "Attacker IP".

إزالة التكرارات والتجميع الفريد: | dedup User و | sort - count.

النتائج:

تقديم المخرجات بصورة مجهزة للعرض المباشر في تقارير فرق الاستجابة للحوادث (SOC Reporting).

Transforming Commands & Aggregation

الهدف: تحويل الـ Raw Logs إلى بيانات إحصائية ورسوم بيانية مجدولة لحساب التكرارات واستخراج السلوكيات العالية الخطورة.

الأوامر والتقنيات:

تجميع الأرقام والإحصائيات: | stats count by User, EventID.

معرفة القيم الأكثر والأقل تكراراً: | top limit=5 User و | rare User.

النتائج:

تحديد الحسابات الأكثر نشاطاً والـ IPs التي تولد أعلى كمية من الأحداث بسرعة.

Log Correlation & GeoIP Enrichment

الهدف: ربط مصادر بيانات متعددة لاستكمال الصورة الجنائية وإثراء عناوين الـ IP ببيانات جغرافية.

الأوامر والتقنيات:

دمج سجلات Sysmon (EventID=1) مع Windows Security (EventID=4624) عبر حقل مشترك:
index="windowslogs" EventID=1 | join LogonId [search index="windowslogs" EventID=4624]

استخراج الموقع الجغرافي للـ IP: | iplocation SourceIp | stats count by Region, Country.

النتائج:

ربط اسم العملية المفتوحة (Image) بـ نوع تسجيل الدخول (LogonType) والـ IP المصدر.

تحديد المناطق والدول التي تنطلق منها الاتصالات.

Anomaly & Outlier Detection

الهدف: كشف الدخول غير المعتاد أو الشاذ عن سلوك المستخدمين الطبيعي (مثل تسجيل الدخول في أوقات متأخرة أو من دول غريبة).

الأوامر والتقنيات:

البحث عن القيم الشاذة تلقائياً: index=vpnlogs | anomalousvalue.

الفلترة الزمنية للمحاولات المشبوهة: index=vpnlogs date_hour=3 | stats count by user.

النتائج:

كشف الحسابات المخترقة التي تقوم بتسجيل الدخول في أوقات غير معتادة (الساعة 3 صباحاً) ومن دول غير مألوفة (Outliers).

💡 أهم الدروس المستفادة (Key Takeaways)

أهمية الـ Correlation: الـ Logs المنفصلة لا تعطي الصورة كاملة؛ ربط Sysmon بـ Windows Security عبر LogonId يربط العملية بدواعي نوع الدخول وسياقه الأمن.

تحسين أداء البحث (Search Performance): تقليل الحقول المسترجعة باستخدام fields وإيقاف الـ Sampling يضمن الدقة والسرعة في التحقيق الجنائي الرقمي.

التحليل الجغرافي والزمني: إثراء البيانات بـ iplocation وفحص أوقات الدخول (date_hour) يمثل خط الدفاع الأول لرصد اختراق الحسابات وشذوذ الـ VPN.
