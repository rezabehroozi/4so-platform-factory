'use strict';

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const state = {
  locale: localStorage.getItem('platformLocale') || 'en',
  session: null,
  currentPage: 'overview',
  catalog: [], catalogReleases: [], catalogTrustKeys: [], catalogSigningIdentity: {}, blueprintCatalogComponents: null, blueprintAuthoringContract: null, blueprintComponentDraft: {}, profiles: [], installationIntegrations: {}, organizations: [], projects: [], clusters: [], imports: [], blueprintReleases: [], blueprintOverlays: [], blueprintEditorReleaseId: null, blueprintEditorRevision: 0,
  baselines: [], baselineDeployments: [], verifications: [], closures: [], runtimeCertifications: [],
  fleetGroups: [], driftScans: [], upgradeCampaigns: [], recoveryCheckpoints: [], fleetHealth: null, tenants: [], tenantPlans: [],
  clusterMaintenanceProfile: null, clusterMaintenanceWindows: [], clusterMaintenanceRuns: [], currentMaintenanceClusterId: '', maintenanceLoadGeneration: 0, providerProfiles: [], providerClusters: [], marketplaceOffers: [], marketplaceInstallations: [], recommendations: [],
  operations: [], audit: [], aiPolicy: {}, aiGuide: {}, aiRuns: [], aiLatestDiagnosis: null, notificationDestinations: [], notificationRoutes: [], notificationEvents: [], notificationDeliveries: [], notificationEventTypes: [], summary: {}, services: [], version: {}, gitRevisionFiles: {}, accessContext: null, organizationMemberships: [], serviceAccounts: [], apiTokens: {}, identityAuthority: null, oidcGroupMappings: [], securityAudit: [], currentEntitlement: null, currentOEMProfile: null,
  degradedRequests: [], pageLoading: false, pageLoadController: null, pageLoadGeneration: 0, autoRefreshTimer: null, autoRefreshGeneration: 0, interactionHoldUntil: 0, lastSubmittedForm: null, lastSubmittedAt: 0, sessionRedirectPending: false, sessionRefreshPromise: null, permissionContextReady: false, gitProviders: [], gitCredentials: [], tableSortPreferences: {}
};

const fa = {
  'nav.platform':'پلتفرم','nav.operate':'عملیات','nav.system':'سیستم','nav.start':'شروع','nav.overview':'نمای کلی','nav.workspace':'سازمان‌ها و پروژه‌ها','nav.infrastructure':'زیرساخت','nav.installation':'برنامه‌ریزی Appliance','nav.clusters':'کلاسترهای متصل','nav.providers':'چرخه عمر Provider','nav.delivery':'تحویل پلتفرم','nav.blueprints':'نسخه‌های Blueprint','nav.marketplace':'مارکت‌پلیس','nav.baselines':'استقرار Baseline','nav.verification':'تأیید Runtime و Closure','nav.fleet':'Fleet و ارتقا','nav.commercial':'تجاری','nav.tenants':'Tenant و OEM','nav.operations':'عملیات','nav.activity':'عملیات و ممیزی','nav.notifications':'اعلان‌ها و مسیریابی','nav.services':'سرویس‌های سیستم','nav.advanced':'پیشرفته','nav.catalog':'کاتالوگ','nav.validator':'ابزار Blueprint',
  'action.createServiceAccount':'ایجاد Service Account','action.grantAccess':'اعطا / بروزرسانی دسترسی','action.revokeAccess':'لغو دسترسی','action.signout':'خروج','action.refresh':'بازخوانی','action.viewAll':'مشاهده همه','action.createOrg':'ایجاد سازمان','action.createProject':'ایجاد پروژه','action.createPlan':'ساخت برنامه','action.clear':'پاک‌کردن','action.createImport':'ساخت درخواست اتصال','action.copy':'کپی','action.verifyProfile':'تأیید پروفایل','action.createCluster':'ساخت درخواست کلاستر','action.getAdvisory':'دریافت پیشنهاد','action.createInstallPlan':'ساخت برنامه نصب','action.createLivePlan':'ساخت برنامه واقعی','action.runVerification':'اجرای تأیید','action.createClosure':'ساخت Closure Campaign','action.createFleet':'ساخت Fleet','action.applyEntitlement':'اعمال Entitlement','action.saveOEM':'ذخیره پروفایل OEM','action.createTenant':'ایجاد Tenant','action.validate':'اعتبارسنجی','action.cancel':'انصراف','action.confirm':'تأیید','action.saveDraft':'ایجاد Draft','action.resetDraft':'پاک‌کردن ویرایشگر','action.compare':'مقایسه',
  'overview.authority':'کنترل‌پلین معتبر پلتفرم خصوصی','overview.heading':'آمادگی پلتفرم و اقدام بعدی اپراتور','overview.description':'پیش از تغییر پلتفرم، آمادگی زنده، موانع و عملیات durable را بررسی کنید.','overview.readiness':'آمادگی Journey محصول','overview.readinessHelp':'هر مرحله از داده واقعی API محاسبه می‌شود.','overview.attention':'نیازمند توجه','overview.attentionHelp':'خطاها و پیش‌نیازهای مسدود که نیازمند اقدام اپراتور هستند.','overview.recent':'فعالیت‌های اخیر','overview.recentHelp':'آخرین عملیات durable و رویدادهای ممیزی.',
  'workspace.automation':'هویت‌های خودکارسازی','workspace.automationHelp':'Service Account و API Token منقضی‌شونده را در محدوده سازمان یا پروژه بسازید. Secret فقط یک‌بار نمایش داده می‌شود و Approval انسانی واگذار نمی‌شود.','workspace.heading':'سازمان‌ها و پروژه‌ها','workspace.description':'مرز مالکیتی موردنیاز همه Workflowهای کلاستر، Tenant، Provider و استقرار را بسازید.','workspace.createOrg':'ایجاد سازمان','workspace.createOrgHelp':'یک نام ماشینی پایدار و نام نمایشی خوانا استفاده کنید.','workspace.createProject':'ایجاد پروژه','workspace.createProjectHelp':'پروژه‌ها منابع و سابقه عملیات را در هر سازمان جدا می‌کنند.','workspace.records':'رکوردهای Workspace','workspace.recordsHelp':'نام نمایشی سازمان را بدون تغییر شناسه منابع ویرایش کنید.','workspace.access':'دسترسی سازمانی','workspace.accessHelp':'محدوده مؤثر دسترسی خود را ببینید و اگر مدیر همان سازمان هستید عضویت را بدون ایجاد Role سراسری مدیریت کنید.',
  'field.projectScope':'محدوده پروژه','field.productRole':'نقش محصول','field.subject':'Subject','field.organizationRole':'نقش سازمانی','field.machineName':'نام ماشینی','field.displayName':'نام نمایشی','field.organization':'سازمان','field.project':'پروژه','field.profile':'پروفایل','field.connectivity':'نوع اتصال','field.provider':'Provider زیرساخت','field.nodes':'آدرس نودهای مدیریت','field.credentialRef':'مرجع Credential','field.sshUser':'کاربر SSH','field.storageClass':'StorageClass تکرارشونده','field.endpoint':'Endpoint عمومی','field.dnsZone':'زون DNS','field.tlsMode':'حالت TLS','field.certificateRef':'مرجع گواهی','field.adminEmail':'ایمیل مدیر Identity','field.objectStorageMode':'Object Storage','field.objectStorageUrl':'Endpoint سازگار با S3','field.bucket':'Bucket','field.prefix':'Prefix','field.expiration':'انقضای Enrollment','field.managementCluster':'کلاستر مدیریت','field.workerClass':'کلاس Worker','field.defaultVersion':'نسخه پیش‌فرض Kubernetes','field.series':'سری‌های major/minor مجاز','field.maxWorkers':'حداکثر Worker','field.providerProfile':'پروفایل Provider تأییدشده','field.kubernetesVersion':'نسخه Kubernetes','field.controlPlane':'تعداد Control Plane','field.workers':'تعداد Worker','field.cluster':'کلاستر متصل','field.offer':'Offer منتشرشده','field.objective':'هدف پیشنهاد','field.baseline':'نسخه Baseline','field.namespace':'Namespace مقصد','field.baselineDeployment':'استقرار Baseline','field.clusters':'کلاسترهای متصل','field.edition':'Edition','field.brandName':'نام برند','field.productTitle':'عنوان محصول','field.supportUrl':'آدرس پشتیبانی','field.logoRef':'مرجع لوگو','field.accent':'رنگ اصلی','field.locale':'زبان پیش‌فرض','field.customDomain':'دامنه اختصاصی','field.plan':'پلن Tenant','field.blueprintJson':'JSON مربوط به Blueprint','field.blueprintName':'نام Blueprint','field.releaseVersion':'نسخه Release','field.certificationLevel':'سطح Certification موردنیاز','field.description':'توضیحات','field.kubernetesMin':'حداقل Kubernetes','field.kubernetesMax':'حداکثر Kubernetes','field.architectures':'معماری‌ها','field.distributionProfiles':'هویت‌های توزیع','field.repository':'آدرس Repository','field.ociRegistry':'Registry مربوط به OCI','field.revisionType':'نوع Revision','field.revision':'Revision','field.evidenceRetention':'مدت نگهداری Evidence (روز)','field.tenantPlans':'پلن‌های مجاز Tenant','field.upgradeFrom':'Releaseهای مبدا ارتقا','field.leftRelease':'Release سمت چپ','field.rightRelease':'Release سمت راست',
  'help.machineName':'فقط حروف کوچک، عدد و خط تیره.','help.nodes':'تعداد دقیق بر اساس پروفایل انتخابی کنترل می‌شود.','help.noSecret':'فقط Reference وارد کنید؛ Credential خام را اینجا قرار ندهید.','help.multiSelect':'برای انتخاب چند مورد از Ctrl/Command استفاده کنید.',
  'installation.heading':'نصب Platform Factory','installation.description':'از ورودی‌های ساختاریافته یک برنامه نصب معتبر بسازید. اجرا در Bootstrap Installer روی Hostهای مدیریت انجام می‌شود.','installation.profile':'پروفایل استقرار','installation.hosts':'Hostها و دسترسی','installation.network':'Endpoint و TLS','installation.backup':'هدف Backup خارج از نود','installation.acceptRisk':'هشدارهای پروفایل و ریسک اعلام‌شده نصب را بررسی و قبول کرده‌ام.','installation.planResult':'برنامه تأییدشده',
  'clusters.heading':'کلاسترها','clusters.description':'Enrollment مربوط به Agent خروجی را تأیید کنید و بدون ذخیره kubeconfig مشتری، Inventory دریافت کنید.','clusters.newImport':'اتصال کلاستر','clusters.newImportHelp':'درخواست در صورت Claim نشدن خودکار منقضی می‌شود.','clusters.enrollment':'Manifest اتصال','clusters.connected':'کلاسترهای متصل','clusters.connectedHelp':'تازگی، Inventory و Capability از Agent واقعی کلاستر می‌آید.','clusters.imports':'درخواست‌های اتصال','clusters.importsHelp':'هر درخواست را مستقل تأیید یا بررسی کنید.',
  'providers.heading':'Providerها','providers.description':'یک ClusterClass مجاز را روی کلاستر مدیریت تأیید و سپس کلاستر اختصاصی Approval-bound ایجاد کنید.','providers.profile':'تأیید پروفایل Provider','providers.profileHelp':'فقط ClusterClass موجود و allowlist‌شده قابل پذیرش است.','providers.cluster':'ایجاد کلاستر اختصاصی','providers.clusterHelp':'ساخت تا زمان بررسی مشخصات دقیق توسط Approver در انتظار می‌ماند.','providers.profiles':'پروفایل‌های Provider','providers.profilesHelp':'نتیجه تأیید و Actionهای موجود.','providers.clusters':'کلاسترهای اختصاصی','providers.clustersHelp':'Create، Approve، Scale، Upgrade، Retry و Delete از هر رکورد.',
  'marketplace.heading':'مارکت‌پلیس و Advisory کنترل‌شده','marketplace.description':'فقط Offerهای منتشرشده با Workflow کامل Baseline قابل نصب‌اند. خروجی Advisory امکان اجرا ندارد.','marketplace.offers':'Offerهای منتشرشده','marketplace.offersHelp':'فقط Offerهایی که Workflow اجرایی پذیرفته‌شده دارند نمایش داده می‌شوند.','marketplace.installations':'نصب‌ها','marketplace.installationsHelp':'Plan، Approval، Retry و Uninstall را از همان رکورد مدیریت کنید.','marketplace.recommendations':'سابقه پیشنهادها','marketplace.recommendationsHelp':'نتایج Advisory ذخیره‌شده همراه با Digestهای Context و Response.',
  'baselines.heading':'استقرار Baseline تأییدشده','baselines.description':'روی Inventory واقعی Plan بسازید، تغییرات دقیق را مرور و صریحاً تأیید کنید و فقط منابع allowlist‌شده را Apply یا Rollback کنید.','baselines.history':'سابقه استقرار','baselines.historyHelp':'هر رکورد فقط Actionهای معتبر وضعیت فعلی خود را نمایش می‌دهد.',
  'verification.heading':'تضمین و تأیید Runtime','verification.description':'Probe digest-pinned را اجرا، Checkها را بررسی، Failure موقت را Retry و Evidence موفق را در Campaign قابل Resume متصل کنید.','verification.run':'اجرای Verification','verification.runHelp':'پس از SUCCEEDED شدن Baseline فعال می‌شود.','verification.closure':'ایجاد Closure Campaign','verification.closureHelp':'Authorityهای موجود را بدون دورزدن Approval هماهنگ می‌کند.','verification.reports':'گزارش‌های Runtime','verification.reportsHelp':'Check، Digest، خطا و Retry نتیجه واقعی Agent.','verification.campaigns':'Closure Campaignها','verification.campaignsHelp':'هر بار یک State durable جلو می‌رود و Failure از Action اصلی Resume می‌شود.','verification.verifiedTitle':'Evidence تأییدشده Closure','verification.verifiedMessage':'اعتبارسنجی مستقل Digest موفق بود.','verification.integrityOnly':'این بررسی فقط یکپارچگی Evidence را تأیید می‌کند؛ Runtime Certified، HA Certified و Production Ready همچنان false هستند.',
  'fleet.health':'سلامت Fleet و پشتیبانی','fleet.healthHelp':'تازگی Inventory، آمادگی نودها، Storage، ظرفیت، شبکه، گواهی‌ها و وضعیت پشتیبانی/EOL آفلاین Kubernetes.','fleet.supportBundle':'بسته پشتیبانی','fleet.supportBundleHelp':'ZIP تشخیصی این پروژه را با Redaction محلی دریافت و با platformctl به‌صورت آفلاین Verify کنید.','fleet.heading':'Fleet','fleet.description':'کلاسترها را گروه‌بندی، Drift واقعی را بخوانید و Baseline تأییدشده را با Canary و Wave محدود Rollout کنید.','fleet.create':'ساخت Fleet Group','fleet.createHelp':'کلاسترهای یک پروژه و سیاست عملیاتی مشترک را انتخاب کنید.','fleet.groups':'Fleet Groupها','fleet.groupsHelp':'Workflow Drift یا Upgrade را از Group شروع کنید.','fleet.scans':'Drift Scanها','fleet.scansHelp':'مقایسه زنده Desired/Observed برای هر کلاستر.','fleet.campaigns':'Upgrade Campaignها','fleet.campaignsHelp':'Approval، Canary، Wave و Halt State قابل مشاهده می‌ماند.',
  'tenants.heading':'Tenant و برندینگ','tenants.description':'Entitlement تجاری را اعمال، Branding سازمان را تنظیم و Namespace Tenantها را از طریق Agent مدیریت کنید.','tenants.entitlement':'Entitlement تجاری','tenants.entitlementHelp':'Edition محدودیت Tenant و دسترسی OEM را تعیین می‌کند.','tenants.oem':'پروفایل OEM','tenants.oemHelp':'از سازمان انتخاب‌شده Load و در همان ذخیره می‌شود.','tenants.create':'ایجاد Namespace Tenant','tenants.createHelp':'فقط Planهای Authority کاتالوگ Tenant قابل انتخاب‌اند.','tenants.environments':'محیط‌های Tenant','tenants.environmentsHelp':'Suspend، Resume، Retry و Delete فقط در وضعیت معتبر نمایش داده می‌شوند.',
  'blueprints.heading':'چرخه عمر نسخه‌های Blueprint','blueprints.description':'استاندارد نسخه‌دار پلتفرم را تعریف کنید، Revisionهای immutable را بررسی کنید، Release تأییدشده را منتشر و مسیر ارتقا را صریح نگهداری کنید.','blueprints.author':'ساخت و ویرایش Draft','blueprints.authorHelp':'هر ذخیره یک Revision immutable جدید می‌سازد. محتوای Published درجا قابل ویرایش نیست.','blueprints.compatibility':'سازگاری','blueprints.delivery':'تحویل GitOps','blueprints.tenancy':'Tenant و Evidence','blueprints.components':'اجزای پلتفرم','blueprints.componentsHelp':'اجزای اجباری همراه محصول روشن و قفل هستند؛ اجزای اختیاری انتخاب صریح اپراتور باقی می‌مانند.','blueprints.upgrades':'مبداهای پشتیبانی‌شده ارتقا','blueprints.upgradesHelp':'فقط Releaseهای همان Project و همان خانواده Blueprint مجاز هستند.','blueprints.lifecycle':'چرخه عمر','blueprints.lifecycleHelp':'پس از ورود به Review تغییر محتوا متوقف می‌شود. انتشار خارج از local development به مدیر جداگانه نیاز دارد.','blueprints.compare':'مقایسه Releaseها','blueprints.compareHelp':'Payloadهای immutable ذخیره‌شده را پیش از تعریف مسیر ارتقای بعدی مقایسه کنید.','blueprints.releases':'Releaseهای Blueprint','blueprints.releasesHelp':'فقط Releaseهای معتبر Persistشده نمایش داده می‌شوند و هیچ رکورد Sample یا Synthetic به پنل تزریق نمی‌شود.','operations.heading':'فعالیت و ممیزی','operations.description':'State، Step، Evidence و سابقه append-only Actor را بررسی کنید.','operations.recent':'عملیات اخیر','operations.recentHelp':'رکورد را باز کنید تا Stepها و Evidence مهرشده را ببینید.','operations.audit':'Audit Trail','operations.auditHelp':'آخرین Actionهای Resource همراه Actor و Revision.','services.heading':'Integration و سرویس‌ها','services.description':'وضعیت واقعی قراردادهای Integration برای Git، Registry، Identity و Reconciliation داخلی.','catalog.heading':'Releaseهای کاتالوگ','catalog.description':'Constraint نسخه، Risk، Wave تحویل و Certification از کاتالوگ همراه محصول.','validator.heading':'ابزارهای برنامه‌ریزی Blueprint','validator.description':'رابط پیشرفته planning-only که Resource را Apply یا Source of Truth مخفی ایجاد نمی‌کند.','validator.warning':'این ابزار فقط Planning Result می‌دهد. برای Workflow اجرایی کلاستر از Marketplace یا Baseline Deployment استفاده کنید.','validator.result':'نتیجه Plan'
};

function t(key, fallback = '') { return state.locale === 'fa' ? (fa[key] || fallback || key) : (fallback || key); }
function applyLocale() {
  document.documentElement.lang = state.locale;
  document.documentElement.dir = state.locale === 'fa' ? 'rtl' : 'ltr';
  $('#language-toggle').textContent = state.locale === 'fa' ? 'EN' : 'FA';
  $$('[data-i18n]').forEach(el => {
    const key = el.dataset.i18n;
    if (!el.dataset.en) el.dataset.en = el.textContent;
    el.textContent = state.locale === 'fa' ? (fa[key] || el.dataset.en) : el.dataset.en;
  });
  updateBreadcrumb();
}

const faDynamic = {
  "Create an organization": "ایجاد سازمان",
  "Organizations": "سازمان‌ها",
  "Connected clusters": "کلاسترهای متصل",
  "Successful baselines": "Baselineهای موفق",
  "Needs attention": "نیازمند توجه",
  "No failed product workflow": "Workflow ناموفق محصول وجود ندارد",
  "Create a project": "ایجاد پروژه",
  "Connect a Kubernetes cluster": "اتصال کلاستر Kubernetes",
  "Apply the certified baseline": "اعمال Baseline تأییدشده",
  "Verify runtime health": "بررسی سلامت Runtime",
  "Close runtime evidence": "بستن شواهد Runtime",
  "No urgent action": "اقدام فوری وجود ندارد",
  "No activity yet": "هنوز فعالیتی ثبت نشده است",
  "Create an organization and start the first workflow.": "یک سازمان ایجاد کنید و اولین Workflow را آغاز کنید.",
  "1. Organization": "۱. سازمان",
  "2. Project": "۲. پروژه",
  "3. Connect infrastructure": "۳. اتصال زیرساخت",
  "No organization selected": "سازمانی انتخاب نشده است",
  "Select an organization to review access.": "برای بررسی دسترسی یک سازمان انتخاب کنید.",
  "OIDC group mapping authority": "مرجع نگاشت گروه OIDC",
  "Map identity-provider groups to product and optional organization/project roles. Realm roles are not authoritative.": "گروه‌های Identity Provider را به نقش‌های محصول و در صورت نیاز سازمان/پروژه نگاشت کنید. Realm Role مرجع نهایی نیست.",
  "OIDC group": "گروه OIDC",
  "Product role": "نقش محصول",
  "Organization scope": "محدوده سازمان",
  "Organization role": "نقش سازمان",
  "Project scope": "محدوده پروژه",
  "Project role": "نقش پروژه",
  "Create mapping": "ایجاد نگاشت",
  "No OIDC group mappings": "نگاشت گروه OIDC وجود ندارد",
  "Create an explicit group mapping before relying on OIDC identities for product access.": "پیش از اتکا به هویت‌های OIDC برای دسترسی محصول، نگاشت گروه صریح ایجاد کنید.",
  "No accessible organization": "سازمان قابل دسترسی وجود ندارد",
  "A platform administrator must create an organization or grant membership.": "مدیر پلتفرم باید سازمان ایجاد کند یا عضویت بدهد.",
  "Infrastructure region": "Region زیرساخت",
  "Platform service integrations": "یکپارچه‌سازی سرویس‌های پلتفرم",
  "Managed services are the safe default. External modes expose only adapter-supported fields and accept secret references instead of plaintext credentials.": "سرویس‌های مدیریت‌شده پیش‌فرض امن هستند. حالت خارجی فقط فیلدهای پشتیبانی‌شده Adapter را نمایش می‌دهد و به‌جای Credential خام، Secret Reference می‌پذیرد.",
  "Git desired state": "Desired State گیت",
  "Mode and provider": "حالت و Provider",
  "PostgreSQL authority": "مرجع PostgreSQL",
  "Evidence and backup storage": "ذخیره‌سازی Evidence و Backup",
  "Identity and SSO": "Identity و SSO",
  "A project is required before a cluster can be connected.": "پیش از اتصال کلاستر باید پروژه ایجاد شود.",
  "Create organization and project": "ایجاد سازمان و پروژه",
  "No connected clusters": "کلاستر متصلی وجود ندارد",
  "Create and approve an enrollment request, then apply its manifest on the target cluster.": "درخواست Enrollment را ایجاد و تأیید کنید، سپس Manifest آن را روی کلاستر مقصد اعمال کنید.",
  "Cluster environment & maintenance": "محیط کلاستر و نگه‌داری",
  "Define the cluster environment, open a bounded maintenance window and run disruption-aware node maintenance through the connected agent.": "محیط کلاستر را تعیین کنید، پنجره نگه‌داری محدود باز کنید و نگه‌داری Node را با توجه به اختلال از طریق Agent متصل اجرا کنید.",
  "Cluster": "کلاستر",
  "Environment": "محیط",
  "Default drain timeout (seconds)": "مهلت پیش‌فرض Drain (ثانیه)",
  "Save environment profile": "ذخیره پروفایل محیط",
  "Window name": "نام پنجره",
  "Starts": "شروع",
  "Ends": "پایان",
  "Max unavailable": "حداکثر خارج از دسترس",
  "Drain timeout (seconds)": "مهلت Drain (ثانیه)",
  "Create maintenance window": "ایجاد پنجره نگه‌داری",
  "Maintenance windows": "پنجره‌های نگه‌داری",
  "Maintenance runs": "اجراهای نگه‌داری",
  "No maintenance windows": "پنجره نگه‌داری وجود ندارد",
  "No maintenance runs": "اجرای نگه‌داری وجود ندارد",
  "No enrollment requests": "درخواست Enrollment وجود ندارد",
  "A project and connected management cluster are required before provider verification.": "پیش از تأیید Provider، پروژه و کلاستر مدیریت متصل لازم است.",
  "Connect a cluster": "اتصال کلاستر",
  "ClusterClass": "ClusterClass",
  "Architecture": "معماری",
  "Distribution": "توزیع",
  "A project is required before a Blueprint release can be authored.": "پیش از ایجاد Blueprint Release باید پروژه وجود داشته باشد.",
  "Visual / API authoring parity": "هم‌ارزی ویرایشگر بصری و API",
  "The visual editor is bound to the same strict Blueprint schema used by the API. Import, export and verify an exact canonical round-trip before saving a release.": "ویرایشگر بصری دقیقاً به همان Schema سخت‌گیرانه Blueprint در API متصل است. پیش از ذخیره Release، Round-trip استاندارد را Import، Export و Verify کنید.",
  "Export visual JSON": "خروجی JSON بصری",
  "Import JSON into visual editor": "ورود JSON به ویرایشگر بصری",
  "Verify API round-trip": "تأیید Round-trip API",
  "Canonical Blueprint JSON": "JSON استاندارد Blueprint",
  "Overlay & field ownership": "Overlay و مالکیت فیلد",
  "Create immutable provider/environment overlays. Paths without an explicit ownership rule remain Blueprint-only and cannot be overridden.": "Overlayهای immutable برای Provider/Environment بسازید. Path بدون قانون مالکیت صریح فقط متعلق به Blueprint می‌ماند و Override نمی‌شود.",
  "Overlay scope": "محدوده Overlay",
  "Overlay name": "نام Overlay",
  "Version": "نسخه",
  "Scope key": "کلید Scope",
  "Changes": "تغییرات",
  "Create immutable overlay": "ایجاد Overlay immutable",
  "No overlays": "Overlay وجود ندارد",
  "Create a provider or environment overlay when a Blueprint explicitly delegates fields.": "وقتی Blueprint فیلدی را صریحاً واگذار می‌کند، Overlay مربوط به Provider یا Environment ایجاد کنید.",
  "Catalog release": "Catalog Release",
  "API version": "نسخه API",
  "Kind": "نوع",
  "Source release": "Release مبدا",
  "Provider overlay": "Overlay مربوط به Provider",
  "Environment overlay": "Overlay مربوط به Environment",
  "Field ownership policy": "سیاست مالکیت فیلد",
  "Rules": "قواعد",
  "Resolve preview": "پیش‌نمایش Resolve",
  "Governance": "حاکمیت",
  "Certification profile details": "جزئیات پروفایل Certification",
  "Runtime certification": "Certification زمان اجرا",
  "Certification runs": "اجراهای Certification",
  "Fresh-install namespace": "Namespace نصب تازه",
  "Queue certification run": "صف اجرای Certification",
  "Compatibility check": "بررسی سازگاری",
  "Evaluate compatibility": "ارزیابی سازگاری",
  "Authentication & authorization audit": "ممیزی احراز هویت و مجوزدهی",
  "Immutable hash-chained security decisions for authentication, product RBAC and organization/project scope authorization.": "تصمیم‌های امنیتی immutable و زنجیره‌شده با Hash برای احراز هویت، RBAC محصول و مجوزدهی Scope سازمان/پروژه.",
  "Audit Trail": "ردپای ممیزی",
  "Audit events": "رویدادهای ممیزی",
  "Notifications & action routing": "اعلان‌ها و مسیریابی اقدام",
  "Destinations": "مقصدها",
  "Create destination": "ایجاد مقصد",
  "Create routing rule": "ایجاد قانون مسیریابی",
  "Delivery history": "تاریخچه تحویل",
  "Dead letters": "Dead Letterها",
  "Event history": "تاریخچه رویداد",
  "Event types": "نوع رویدادها",
  "Git provider & credential authority": "مرجع Provider و Credential گیت",
  "Create credential reference": "ایجاد Credential Reference",
  "Ensure desired-state repository": "اطمینان از Repository مربوط به Desired State",
  "Publish signed desired-state revision": "انتشار Revision امضاشده Desired State",
  "Git organization": "سازمان گیت",
  "Repository": "Repository",
  "Revision ID": "شناسه Revision",
  "Revision digest": "Digest مربوط به Revision",
  "Delivery mode": "حالت تحویل",
  "File path": "مسیر فایل",
  "File content": "محتوای فایل",
  "Add or replace file": "افزودن یا جایگزینی فایل",
  "Publish revision": "انتشار Revision",
  "Signed & private catalog governance": "حاکمیت Catalog امضاشده و خصوصی",
  "Governed catalog releases": "Catalog Releaseهای حاکمیتی",
  "Create catalog release": "ایجاد Catalog Release",
  "Create immutable candidate": "ایجاد Candidate immutable",
  "Components included in this release": "اجزای این Release",
  "Active trust keys": "کلیدهای اعتماد فعال",
  "Catalog digest": "Digest کاتالوگ",
  "Catalog name": "نام Catalog",
  "Initial channel:": "Channel اولیه:",
  "Credential rotation / revocation": "Rotation / Revocation مربوط به Credential",
  "Credential state": "وضعیت Credential",
  "Authority": "مرجع کنترل",
  "Description": "توضیحات",
  "Enabled": "فعال",
  "Endpoint": "Endpoint",
  "Method": "روش",
  "Name": "نام",
  "Components": "اجزا",
  "Kubernetes version": "نسخه Kubernetes",
  "Connected cluster": "کلاستر متصل",
  "Project": "پروژه",
  "Organization": "سازمان",
  "No provider profiles": "پروفایل Provider وجود ندارد",
  "Connect a Cluster API management cluster and verify its admitted ClusterClass.": "یک کلاستر مدیریت Cluster API متصل و ClusterClass پذیرفته‌شده آن را تأیید کنید.",
  "No dedicated clusters": "کلاستر اختصاصی وجود ندارد",
  "Verify a provider profile and create the first approval-bound cluster request.": "یک پروفایل Provider را تأیید و اولین درخواست کلاستر Approval-bound را ایجاد کنید.",
  "No published offers": "Offer منتشرشده‌ای وجود ندارد",
  "An offer is hidden until its complete runtime workflow is admitted.": "Offer تا زمان پذیرفته‌شدن Workflow کامل Runtime نمایش داده نمی‌شود.",
  "No marketplace installations": "نصب Marketplace وجود ندارد",
  "Select an offer and connected cluster to create the first plan.": "یک Offer و کلاستر متصل انتخاب کنید تا اولین Plan ساخته شود.",
  "No recommendations": "پیشنهادی وجود ندارد",
  "Enter a concrete objective to request an advisory-only recommendation.": "یک هدف مشخص وارد کنید تا پیشنهاد صرفاً Advisory دریافت شود.",
  "No baseline deployments": "استقرار Baseline وجود ندارد",
  "Connect a cluster and create the first live plan.": "یک کلاستر متصل و اولین Plan واقعی را ایجاد کنید.",
  "No runtime verification": "تأیید Runtime وجود ندارد",
  "Apply a baseline successfully, then run the digest-pinned probe.": "Baseline را موفق Apply و سپس Probe قفل‌شده با Digest را اجرا کنید.",
  "No closure campaigns": "Closure Campaign وجود ندارد",
  "Select a baseline deployment and create the first resumable campaign.": "یک استقرار Baseline انتخاب و اولین Campaign قابل Resume را ایجاد کنید.",
  "No fleet groups": "Fleet Group وجود ندارد",
  "Select connected clusters and create the first fleet group.": "کلاسترهای متصل را انتخاب و اولین Fleet Group را ایجاد کنید.",
  "No drift scans": "Drift Scan وجود ندارد",
  "Run a live read-only drift scan from a fleet group.": "یک Drift Scan زنده و Read-only از Fleet Group اجرا کنید.",
  "No upgrade campaigns": "Upgrade Campaign وجود ندارد",
  "Create an upgrade campaign from an eligible fleet group.": "از Fleet Group واجد شرایط یک Upgrade Campaign بسازید.",
  "No tenant environments": "محیط Tenant وجود ندارد",
  "Apply an entitlement and create the first namespace tenant.": "Entitlement را اعمال و اولین Namespace Tenant را ایجاد کنید.",
  "No durable operations": "عملیات Durable وجود ندارد",
  "Product workflow operations will appear here.": "عملیات Workflowهای واقعی محصول اینجا نمایش داده می‌شوند.",
  "No audit events": "رویداد Audit وجود ندارد",
  "Resource mutations will be recorded here.": "تغییرات Resource اینجا ثبت می‌شوند.",
  "No system services": "سرویس سیستمی وجود ندارد",
  "System service integration records are unavailable.": "رکورد Integration سرویس‌های سیستم موجود نیست.",
  "No files added": "فایلی اضافه نشده است",
  "Add at least one explicit repository file before publishing.": "پیش از انتشار حداقل یک فایل صریح Repository اضافه کنید.",
  "Details": "جزئیات",
  "Inspect": "بررسی",
  "Edit": "ویرایش",
  "Approve": "تأیید",
  "Approve apply": "تأیید Apply",
  "Approve install": "تأیید نصب",
  "Approve campaign": "تأیید Campaign",
  "Advance campaign": "پیشبرد Campaign",
  "Advance one step": "یک مرحله پیشروی",
  "Retry failed step": "تلاش مجدد مرحله ناموفق",
  "Retry verification": "تلاش مجدد تأیید",
  "Verify evidence": "اعتبارسنجی Evidence",
  "Verified closure evidence": "Evidence تأییدشده Closure",
  "Independent digest verification passed.": "اعتبارسنجی مستقل Digest موفق بود.",
  "Roll back": "Rollback",
  "Run drift scan": "اجرای Drift Scan",
  "Create upgrade campaign": "ساخت Campaign ارتقا",
  "Suspend": "تعلیق",
  "Resume": "ادامه",
  "Delete": "حذف",
  "Remove": "حذف",
  "Uninstall": "حذف نصب",
  "Revoke agent access": "لغو دسترسی Agent",
  "Scale": "تغییر مقیاس",
  "Upgrade": "ارتقا",
  "Continue": "ادامه",
  "Cancel": "انصراف",
  "No plan changes are available yet. The connected agent may still be planning.": "هنوز تغییری در Plan موجود نیست؛ Agent متصل ممکن است در حال برنامه‌ریزی باشد.",
  "Unable to load": "بارگذاری ناموفق بود",
  "Approval requires platform-admin.": "تأیید این عملیات نیازمند نقش platform-admin است.",
  "A different platform administrator must approve this request.": "این درخواست باید توسط مدیر پلتفرم دیگری تأیید شود.",
  "Read-only session": "نشست فقط خواندنی"
};
const dynamicOriginalText = new WeakMap();
let dynamicLocalizationBusy = false;
function localizeDynamicTree(root = document.body) {
  if (!root || dynamicLocalizationBusy) return; dynamicLocalizationBusy = true;
  const walker=document.createTreeWalker(root,NodeFilter.SHOW_TEXT),nodes=[];while(walker.nextNode())nodes.push(walker.currentNode);
  for(const node of nodes){const parent=node.parentElement;if(!parent||parent.closest('script,style,pre,code,.technical,[data-i18n]'))continue;const trimmed=node.nodeValue.trim();if(state.locale==='fa'&&faDynamic[trimmed]){dynamicOriginalText.set(node,node.nodeValue);const lead=node.nodeValue.match(/^\s*/)?.[0]||'',trail=node.nodeValue.match(/\s*$/)?.[0]||'';node.nodeValue=lead+faDynamic[trimmed]+trail;}else if(state.locale!=='fa'&&dynamicOriginalText.has(node)){node.nodeValue=dynamicOriginalText.get(node);dynamicOriginalText.delete(node);}}
  dynamicLocalizationBusy=false;
}
let dynamicLocalizationScheduled=false;
const dynamicLocalizationObserver=new MutationObserver(()=>{
  if(dynamicLocalizationBusy||state.locale!=='fa'||dynamicLocalizationScheduled)return;
  dynamicLocalizationScheduled=true;
  requestAnimationFrame(()=>{dynamicLocalizationScheduled=false;localizeDynamicTree(document.body);});
});
dynamicLocalizationObserver.observe(document.body,{subtree:true,childList:true,characterData:true});

const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const technical = value => `<span class="technical">${esc(value || '—')}</span>`;
const shortDigest = value => value ? `${esc(value.slice(0, 18))}…${esc(value.slice(-8))}` : '—';
const formatDate = value => {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? esc(value) : new Intl.DateTimeFormat(state.locale === 'fa' ? 'fa-IR' : 'en-GB', {dateStyle:'medium', timeStyle:'short'}).format(date);
};
const statusClass = value => {
  const s = String(value || '').toUpperCase();
  if (['SUCCEEDED','ACTIVE','READY','APPROVED','CLAIMED','HEALTHY','PASS','ONLINE','ROLLED_BACK'].includes(s)) return 'success';
  if (['FAILED','ERROR','OFFLINE','EXPIRED','REVOKED','HALTED','DEAD_LETTER'].includes(s)) return 'danger';
  if (s.includes('WAIT') || s.includes('PENDING') || s.includes('QUEUED') || s.includes('RUNNING') || s.includes('PLANNING') || s.includes('APPLYING') || s.includes('VERIFYING') || s.includes('ROLL')) return 'warning';
  return 'neutral';
};
const badge = value => `<span class="badge ${statusClass(value)}">${esc(value || 'unknown')}</span>`;
const detailRow = (label, value, raw = false) => `<div class="detail-row"><span>${esc(label)}</span><span${raw ? ' class="technical" dir="ltr"' : ''}>${raw ? esc(value || '—') : (value ?? '—')}</span></div>`;
const emptyState = (title, message, page = '', action = '') => `<div class="empty-state"><h3>${esc(title)}</h3><p>${esc(message)}</p>${page ? `<button class="primary" type="button" data-navigate="${esc(page)}">${esc(action || 'Continue')}</button>` : ''}</div>`;
const errorState = message => `<div class="empty-state error-state"><h3>Unable to load</h3><p>${esc(message)}</p></div>`;
const sourceUnavailable = labels => {
  const wanted = new Set((Array.isArray(labels) ? labels : [labels]).filter(Boolean));
  return state.degradedRequests.some(item => wanted.has(item.label));
};
const unavailableState = label => {
  const fa=state.locale==='fa';
  const title=fa?'داده موقتاً در دسترس نیست':`${label} unavailable`;
  const message=fa?'منبع این بخش پاسخ نداده است. سایر بخش‌های صفحه ممکن است همچنان به‌روز باشند.':'This data source is temporarily unavailable. Other sections may still be current.';
  const action=fa?'تلاش دوباره برای این صفحه':'Retry this page';
  return `<div class="empty-state unavailable-state"><h3>${esc(title)}</h3><p>${esc(message)}</p><button class="secondary" type="button" data-retry-current>${esc(action)}</button></div>`;
};

function dataTable(label, headers, rows, emptyTitle, emptyMessage, options = {}) {
  if (options.source && sourceUnavailable(options.source)) return unavailableState(label);
  if (!rows.length) return emptyState(emptyTitle, emptyMessage);
  const tableKey = String(options.key || options.source || label);
  const tableHeaders = headers.map((header, index) => {
    const sortable = header.sortable !== false && String(header.label).toLowerCase() !== 'actions';
    const className = header.className ? ` class="${esc(header.className)}"` : '';
    const sortType = header.sortType || (String(header.className || '').includes('numeric') ? 'numeric' : String(header.className || '').includes('timestamp') ? 'timestamp' : 'text');
    const content = sortable ? `<button type="button" class="data-table-sort" data-table-sort-index="${index}" data-sort-type="${esc(sortType)}"><span>${esc(header.label)}</span><span class="sort-indicator" aria-hidden="true">↕</span></button>` : esc(header.label);
    return `<th scope="col"${className}${sortable ? ' aria-sort="none"' : ''}>${content}</th>`;
  }).join('');
  return `<div class="data-table-shell" role="region" aria-label="${esc(label)}" tabindex="0"><table class="data-table" data-table-key="${esc(tableKey)}"><caption class="sr-only">${esc(label)}</caption><thead><tr>${tableHeaders}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
}
const tableCell = (value, className = '', sortValue = null) => `<td${className ? ` class="${esc(className)}"` : ''}${sortValue !== null && sortValue !== undefined ? ` data-sort-value="${esc(sortValue)}"` : ''}>${value ?? '—'}</td>`;
const tableRow = (cells, attrs = '') => `<tr data-record-row ${attrs}>${cells.join('')}</tr>`;
const idempotency = prefix => `${prefix}-${Date.now()}-${crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2)}`;
const apiTokenPermissionProfiles = account => account?.productRole==='platform-operator' ? [
  {value:'read',label:'Read only'},
  {value:'read,mcp.read',label:'Read + MCP context'},
  {value:'read,mcp.read,ai.diagnose',label:'Read + MCP + AI diagnosis'},
  {value:'read,operate,mcp.read,ai.diagnose',label:'Full operator automation'}
] : [
  {value:'read',label:'Read only'},
  {value:'read,mcp.read',label:'Read + MCP context'}
];
const apiTokenPermissionsFromProfile = value => String(value||'read').split(',').map(item=>item.trim()).filter(Boolean);
const apiTokenPermissionProfileValue = permissions => {
  const values=new Set(permissions||[]);
  if(values.has('operate')&&values.has('mcp.read')&&values.has('ai.diagnose'))return 'read,operate,mcp.read,ai.diagnose';
  if(values.has('ai.diagnose'))return 'read,mcp.read,ai.diagnose';
  if(values.has('mcp.read'))return 'read,mcp.read';
  if(values.has('operate'))return 'read,operate,mcp.read,ai.diagnose';
  return 'read';
};

function sessionRoles() { return Array.isArray(state.session?.roles) ? state.session.roles : []; }
function isPermissionContext(value) {
  return !!value && typeof value==='object' && !Array.isArray(value) &&
    value.effectiveOrganizationRoles && typeof value.effectiveOrganizationRoles==='object' && !Array.isArray(value.effectiveOrganizationRoles) &&
    value.effectiveProjectRoles && typeof value.effectiveProjectRoles==='object' && !Array.isArray(value.effectiveProjectRoles);
}
function isLocalSession() { return state.session?.sub === 'local-development'; }
function canOperate() { return isLocalSession() || sessionRoles().includes('platform-admin') || sessionRoles().includes('platform-operator'); }
function canAdminister() { return isLocalSession() || sessionRoles().includes('platform-admin'); }
function canApprove(resource) {
  if (isLocalSession()) return true;
  return sessionRoles().includes('platform-admin') && state.session?.sub && state.session.sub !== resource?.requestedBy;
}
function approvalControl(resource, label, attributes) {
  if (canApprove(resource)) return `<button type="button" class="primary small-button" ${attributes}>${esc(label)}</button>`;
  const reason = !sessionRoles().includes('platform-admin') ? 'Approval requires platform-admin.' : 'A different platform administrator must approve this request.';
  return `<span class="approval-note" title="${esc(reason)}">${esc(reason)}</span>`;
}
const scopeRoleRanks={
  'organization-viewer':1,'project-viewer':1,
  'organization-operator':2,'project-operator':2,
  'organization-admin':3,'project-admin':3
};
function effectiveOrganizationRole(organizationId) {
  if(!organizationId)return '';
  if(isLocalSession()||state.accessContext?.allOrganizations||canAdminister())return 'organization-admin';
  return state.accessContext?.effectiveOrganizationRoles?.[organizationId]||'';
}
function effectiveProjectRole(projectId) {
  if(!projectId)return '';
  if(isLocalSession()||state.accessContext?.allOrganizations||canAdminister())return 'project-admin';
  return state.accessContext?.effectiveProjectRoles?.[projectId]||'';
}
function scopeRoleAllows(role, required='write') {
  const rank=scopeRoleRanks[role]||0;
  return rank >= (required==='admin'?3:2);
}
function setScopedAccess(element, {projectId='',organizationId='',access='write',requiredGlobalRole=''} = {}) {
  if(!element)return;
  if(projectId)element.dataset.projectScope=projectId;else delete element.dataset.projectScope;
  if(organizationId)element.dataset.organizationScope=organizationId;else delete element.dataset.organizationScope;
  if(access&&access!=='write')element.dataset.scopeAccess=access;else delete element.dataset.scopeAccess;
  if(requiredGlobalRole)element.dataset.requiredGlobalRole=requiredGlobalRole;else delete element.dataset.requiredGlobalRole;
}
function clusterRecord(clusterId) {
  return state.clusters.map(row=>row.cluster||row).find(item=>item.id===clusterId)||null;
}
function projectForCluster(clusterId) { return clusterRecord(clusterId)?.projectId||''; }
function scopeActionElements(selector, records, recordId, options) {
  $$(selector).forEach(element=>{
    const record=records.find(item=>recordId(element,item));
    if(!record)return;
    setScopedAccess(element,options(element,record)||{});
  });
}
function applyKnownMutationScopes() {
  // Static authority surfaces.
  setScopedAccess($('#organization-form'),{requiredGlobalRole:'platform-admin'});
  setScopedAccess($('#oidc-group-mapping-form'),{requiredGlobalRole:'platform-admin'});
  setScopedAccess($('#project-form'),{organizationId:$('#project-organization')?.value||'',access:'admin'});
  setScopedAccess($('#membership-form'),{organizationId:$('#membership-organization')?.value||'',access:'admin'});
  setScopedAccess($('#service-account-form'),{organizationId:$('#service-account-organization')?.value||'',access:'admin'});
  setScopedAccess($('#cluster-import-form'),{projectId:$('#cluster-project')?.value||''});

  const maintenanceProject=projectForCluster($('#maintenance-cluster-select')?.value||'');
  setScopedAccess($('#maintenance-profile-form'),{projectId:maintenanceProject});
  setScopedAccess($('#maintenance-window-form'),{projectId:maintenanceProject});
  setScopedAccess($('#maintenance-window-grid'),{projectId:maintenanceProject});
  setScopedAccess($('#maintenance-run-grid'),{projectId:maintenanceProject});

  const providerProject=$('#provider-project')?.value||'';
  setScopedAccess($('#provider-profile-form'),{projectId:providerProject,requiredGlobalRole:'platform-admin'});
  setScopedAccess($('#provider-cluster-form'),{projectId:providerProject});

  setScopedAccess($('#blueprint-release-form'),{projectId:$('#blueprint-project')?.value||''});
  setScopedAccess($('#blueprint-overlay-form'),{projectId:$('#blueprint-overlay-project')?.value||''});

  const marketplaceProject=projectForCluster($('#marketplace-cluster')?.value||'');
  setScopedAccess($('#marketplace-form'),{projectId:marketplaceProject});
  setScopedAccess($('#marketplace-recommend'),{projectId:marketplaceProject});
  const baselineProject=projectForCluster($('#baseline-cluster')?.value||'');
  setScopedAccess($('#baseline-form'),{projectId:baselineProject});
  const verificationDeployment=state.baselineDeployments.find(item=>item.id===$('#verification-baseline')?.value);
  setScopedAccess($('#verification-form'),{projectId:verificationDeployment?.projectId||''});
  const closureDeployment=state.baselineDeployments.find(item=>item.id===$('#closure-baseline')?.value);
  setScopedAccess($('#closure-form'),{projectId:closureDeployment?.projectId||''});
  setScopedAccess($('#runtime-certification-form'),{projectId:$('#runtime-certification-project')?.value||''});

  setScopedAccess($('#recovery-checkpoint-form'),{projectId:projectForCluster($('#recovery-cluster')?.value||'')});
  setScopedAccess($('#fleet-group-form'),{projectId:$('#fleet-project')?.value||''});

  const tenantOrganization=$('#tenant-organization')?.value||'';
  setScopedAccess($('#entitlement-form'),{organizationId:tenantOrganization,access:'admin',requiredGlobalRole:'platform-admin'});
  setScopedAccess($('#oem-form'),{organizationId:tenantOrganization,access:'admin',requiredGlobalRole:'platform-admin'});
  setScopedAccess($('#tenant-form'),{projectId:$('#tenant-project')?.value||''});

  const destinationOrganization=$('#notification-destination-organization')?.value||'';
  const destinationNeedsProcessSecret=Boolean($('#notification-destination-auth-env')?.value.trim()||$('#notification-destination-hmac-env')?.value.trim());
  setScopedAccess($('#notification-destination-form'),{organizationId:destinationOrganization,access:'admin',requiredGlobalRole:destinationNeedsProcessSecret?'platform-admin':''});
  const routeProject=$('#notification-route-project')?.value||'';
  setScopedAccess($('#notification-route-form'),routeProject?{projectId:routeProject}:{organizationId:$('#notification-route-organization')?.value||''});

  for(const id of ['git-credential-create-form','git-provider-create-form','git-credential-rotate-form','git-repository-form','git-revision-form'])setScopedAccess($(`#${id}`),{requiredGlobalRole:'platform-admin'});

  const trustOrganization=$('#catalog-trust-organization')?.value||'';
  setScopedAccess($('#catalog-trust-form'),trustOrganization?{organizationId:trustOrganization,access:'admin'}:{requiredGlobalRole:'platform-admin'});
  const catalogVisibility=$('#catalog-release-visibility')?.value||'PLATFORM';
  const catalogOrganization=$('#catalog-release-organization')?.value||'';
  setScopedAccess($('#catalog-release-form'),catalogVisibility==='PLATFORM'?{requiredGlobalRole:'platform-admin'}:{organizationId:catalogOrganization});

  // Record-level scopes. These prevent a global platform-operator from seeing a
  // writable surface when its effective organization/project role is viewer.
  $$('[data-org-edit]').forEach(button=>setScopedAccess(button,{organizationId:button.dataset.orgEdit,access:'admin'}));
  $$('[data-membership-revoke]').forEach(button=>setScopedAccess(button,{organizationId:button.dataset.org,access:'admin'}));
  $$('[data-oidc-mapping-revoke]').forEach(button=>setScopedAccess(button,{requiredGlobalRole:'platform-admin'}));
  scopeActionElements('[data-service-account-action]',state.serviceAccounts,(el,item)=>el.dataset.id===item.id,()=>({organizationId:$('#service-account-organization')?.value||'',access:'admin'}));
  scopeActionElements('[data-api-token-action]',state.serviceAccounts,(el,item)=>el.dataset.accountId===item.id,(_el,item)=>({organizationId:item.organizationId||$('#service-account-organization')?.value||'',access:'admin'}));
  scopeActionElements('[data-import-action]',state.imports,(el,item)=>el.dataset.id===item.id,(el,item)=>({projectId:item.projectId||'',requiredGlobalRole:el.dataset.importAction==='approve'?'platform-admin':''}));
  $$('[data-cluster-action="revoke"]').forEach(button=>setScopedAccess(button,{requiredGlobalRole:'platform-admin'}));

  scopeActionElements('[data-provider-profile-action]',state.providerProfiles,(el,item)=>el.dataset.id===item.id,()=>({projectId:providerProject,requiredGlobalRole:'platform-admin'}));
  scopeActionElements('[data-provider-cluster-action]',state.providerClusters,(el,item)=>el.dataset.id===item.id,(_el,item)=>({projectId:item.projectId||providerProject}));
  scopeActionElements('[data-marketplace-action]',state.marketplaceInstallations.map(v=>v.installation||v),(el,item)=>el.dataset.id===item.id,(_el,item)=>({projectId:item.projectId||''}));
  scopeActionElements('[data-baseline-action]',state.baselineDeployments,(el,item)=>el.dataset.id===item.id,(_el,item)=>({projectId:item.projectId||''}));
  scopeActionElements('[data-verification-action]',state.verifications,(el,item)=>el.dataset.id===item.id,(_el,item)=>({projectId:item.projectId||''}));
  scopeActionElements('[data-certification-action]',state.runtimeCertifications,(el,item)=>el.dataset.id===item.id,(_el,item)=>({projectId:item.projectId||''}));
  scopeActionElements('[data-closure-action]',state.closures,(el,item)=>el.dataset.id===item.id,(_el,item)=>({projectId:item.projectId||''}));
  scopeActionElements('[data-recovery-action]',state.recoveryCheckpoints,(el,item)=>el.dataset.id===item.id,(_el,item)=>({projectId:item.projectId||''}));
  scopeActionElements('[data-fleet-action]',state.fleetGroups,(el,item)=>el.dataset.id===item.id,(_el,item)=>({projectId:item.projectId||''}));
  scopeActionElements('[data-upgrade-action]',state.upgradeCampaigns,(el,item)=>el.dataset.id===item.id,(_el,item)=>({projectId:item.projectId||''}));
  $$('[data-drift-action]').forEach(button=>{const scan=state.driftScans.find(item=>item.id===button.dataset.scanId);if(scan)setScopedAccess(button,{projectId:scan.projectId||''});});
  $$('[data-agent-certificate-action]').forEach(button=>setScopedAccess(button,{requiredGlobalRole:'platform-admin'}));
  scopeActionElements('[data-tenant-action]',state.tenants,(el,item)=>el.dataset.id===item.id,(el,item)=>({projectId:item.projectId||'',requiredGlobalRole:el.dataset.tenantAction==='approve'?'platform-admin':''}));
  $$('[data-operation-cancel]').forEach(button=>{const op=state.operations.find(item=>item.id===button.dataset.operationCancel);if(op)setScopedAccess(button,{projectId:op.projectId||''});});

  scopeActionElements('[data-notification-destination-action]',state.notificationDestinations,(el,item)=>el.dataset.id===item.id,(_el,item)=>({organizationId:item.organizationId||'',access:'admin'}));
  scopeActionElements('[data-notification-route-action]',state.notificationRoutes,(el,item)=>el.dataset.id===item.id,(_el,item)=>item.projectId?({projectId:item.projectId}):({organizationId:item.organizationId||''}));

  $$('[data-git-provider-action],[data-git-pr-action],[data-git-lkg-rollback]').forEach(button=>setScopedAccess(button,{requiredGlobalRole:'platform-admin'}));
  scopeActionElements('[data-blueprint-action]',state.blueprintReleases,(el,item)=>el.dataset.id===item.id,(el,item)=>({projectId:item.projectId||'',access:['request-changes','publish','deprecate','revoke'].includes(el.dataset.blueprintAction)?'admin':'write'}));
  scopeActionElements('[data-catalog-trust-action]',state.catalogTrustKeys,(el,item)=>el.dataset.id===item.id,(_el,item)=>item.organizationId?({organizationId:item.organizationId,access:'admin'}):({requiredGlobalRole:'platform-admin'}));
  scopeActionElements('[data-catalog-action]',state.catalogReleases,(el,item)=>el.dataset.id===item.id,(el,item)=>{
    const admin=['request-changes','publish','deprecate','revoke'].includes(el.dataset.catalogAction);
    if(item.visibility==='PLATFORM')return {requiredGlobalRole:'platform-admin'};
    return {organizationId:item.organizationId||'',access:admin?'admin':'write'};
  });
}
function scopedMutationReason(button) {
  if(!canOperate())return 'Read-only session';
  const adminHolder=button.closest('[data-required-global-role="platform-admin"]');
  if(adminHolder&&!canAdminister())return 'platform-admin is required';
  if(!isLocalSession()&&!canAdminister()&&!state.permissionContextReady)return 'Permission scope is temporarily unavailable';
  const projectHolder=button.closest('[data-project-scope]');
  if(projectHolder){
    const required=projectHolder.dataset.scopeAccess||'write';
    const role=effectiveProjectRole(projectHolder.dataset.projectScope);
    if(!scopeRoleAllows(role,required))return required==='admin'?'Project administrator access is required':'Project write access is required';
  }
  const organizationHolder=button.closest('[data-organization-scope]');
  if(organizationHolder){
    const required=organizationHolder.dataset.scopeAccess||'write';
    const role=effectiveOrganizationRole(organizationHolder.dataset.organizationScope);
    if(!scopeRoleAllows(role,required))return required==='admin'?'Organization administrator access is required':'Organization write access is required';
  }
  return '';
}
const explicitMutationKeys=new Set(['operationCancel','membershipRevoke','oidcMappingRevoke','orgEdit','gitLkgRollback','notificationRetryDeadLetter']);
function isMutationButton(button) {
  if(!(button instanceof HTMLButtonElement))return false;
  const viewerSafe = button.dataset.viewerSafe==='true' || button.closest('form')?.dataset.viewerSafe==='true';
  if(viewerSafe)return false;
  if(button.matches('form button[type="submit"]'))return true;
  const actionEntry = Object.entries(button.dataset).find(([key]) => key.endsWith('Action'));
  const explicitMutation=Object.keys(button.dataset).some(key=>explicitMutationKeys.has(key));
  if (!actionEntry && !explicitMutation) return false;
  const action = String(actionEntry?.[1] || '').toLowerCase();
  return explicitMutation || !['inspect','view','timeline','bundle','impact'].includes(action);
}
function setIntrinsicDisabled(control, disabled) {
  if(!control)return;
  if(control.dataset?.accessDisabled==='true'){
    control.dataset.accessPriorDisabled=disabled?'true':'false';
    control.disabled=true;
    return;
  }
  control.disabled=disabled;
}
function setAccessDisabled(button, disabled, reason='Read-only session') {
  if(disabled){
    if(button.dataset.accessDisabled!=='true'){
      button.dataset.accessDisabled='true';
      button.dataset.accessPriorDisabled=button.disabled?'true':'false';
      button.dataset.accessHadTitle=button.hasAttribute('title')?'true':'false';
      button.dataset.accessPriorTitle=button.getAttribute('title')||'';
    }
    button.disabled=true;
    button.title=reason;
    return;
  }
  if(button.dataset.accessDisabled!=='true')return;
  button.disabled=button.dataset.accessPriorDisabled==='true';
  if(button.dataset.accessHadTitle==='true')button.setAttribute('title',button.dataset.accessPriorTitle||'');
  else button.removeAttribute('title');
  delete button.dataset.accessDisabled;
  delete button.dataset.accessPriorDisabled;
  delete button.dataset.accessHadTitle;
  delete button.dataset.accessPriorTitle;
}
function applyAccessMode(root = document) {
  applyKnownMutationScopes();
  const readOnly = !canOperate();
  document.body.classList.toggle('read-only-session', readOnly);
  document.body.dataset.accessRole = isLocalSession() ? 'local-admin' : (sessionRoles()[0] || 'unassigned');
  $$('[data-access-disabled="true"]',root).forEach(button=>setAccessDisabled(button,false));
  $$('button',root).filter(isMutationButton).forEach(button=>{
    const reason=scopedMutationReason(button);
    if(reason)setAccessDisabled(button,true,reason);
  });
}
const permissionScopeChangeDrivers=new Set([
  'project-organization','membership-organization','service-account-organization','cluster-project','maintenance-cluster-select',
  'provider-project','blueprint-project','blueprint-overlay-project','marketplace-cluster','baseline-cluster','verification-baseline',
  'closure-baseline','runtime-certification-project','recovery-cluster','fleet-project','tenant-organization','tenant-project',
  'notification-destination-organization','notification-route-organization','notification-route-project','catalog-trust-organization',
  'catalog-release-visibility','catalog-release-organization'
]);
document.addEventListener('change',event=>{if(permissionScopeChangeDrivers.has(event.target?.id))queueMicrotask(()=>applyAccessMode());});
document.addEventListener('input',event=>{if(['notification-destination-auth-env','notification-destination-hmac-env'].includes(event.target?.id))queueMicrotask(()=>applyAccessMode());});

function invalidateDestructiveConfirmationOnDemotion(previousCanOperate) {
  if(!previousCanOperate || canOperate())return;
  const dialog=$('#confirm-dialog');
  if(dialog?.open)dialog.close('cancel');
}

async function api(path, options = {}) {
  const request = {...options, headers: {...(options.headers || {})}};
  const method = String(request.method || 'GET').toUpperCase();
  if (method === 'GET' && !request.signal && state.pageLoadController) request.signal = state.pageLoadController.signal;
  const mutation = ['POST','PUT','PATCH','DELETE'].includes(method);
  const submittedForm = mutation && state.lastSubmittedForm && (Date.now()-state.lastSubmittedAt)<500 ? state.lastSubmittedForm : null;
  if (mutation) { state.lastSubmittedForm = null; state.lastSubmittedAt = 0; }
  const viewerSafePost = ['/api/v1/blueprints/validate','/api/v1/blueprints/authoring-roundtrip','/api/v1/blueprints/resolve','/api/v1/plans','/api/v1/compatibility/evaluate','/api/v1/installations/plans','/api/v1/blueprint-releases/compare','/api/v1/runtime-closure-reports/verify','/api/v1/support-bundles'].includes(path);
  if (state.session && ['POST','PUT','PATCH','DELETE'].includes(method) && !viewerSafePost && !canOperate()) {
    // A viewer may have been promoted after this tab loaded. Refresh session
    // authority before blocking a mutation purely from stale client state.
    await syncSessionAuthority({redirectOnUnauthorized:true});
    if (!canOperate()) {
      const error = new Error('This session is read-only. platform-operator or platform-admin is required.');
      error.code = 'OPERATOR_ROLE_REQUIRED'; error.status = 403; throw error;
    }
  }
  if (request.body !== undefined && typeof request.body !== 'string') {
    request.headers['Content-Type'] = 'application/json';
    request.body = JSON.stringify(request.body);
  }
  const response = await fetch(path, request);
  const contentType = response.headers.get('content-type') || '';
  const body = contentType.includes('application/json') ? await response.json() : await response.text();
  if (!response.ok) {
    let message = body?.error?.message || body?.message || (typeof body === 'string' ? body : `HTTP ${response.status}`);
    if (response.status === 409 || response.status === 412) message = `This resource changed while you were viewing it. Refresh the latest revision before retrying. ${message}`;
    const error = new Error(message);
    error.code = body?.error?.code || `HTTP_${response.status}`;
    error.status = response.status;
    error.body = body;
    if (response.status === 401 && path.startsWith('/api/')) {
      error.sessionExpired = true;
      handleSessionExpired();
    } else if (response.status === 403 && path.startsWith('/api/') && state.session) {
      // Backend authorization is authoritative and can change while this tab is
      // open (for example through OIDC group mapping). Re-sync the visible
      // permission surface after a denial instead of leaving stale controls live.
      await syncSessionAuthority({redirectOnUnauthorized:true});
    }
    throw error;
  }
  if (mutation && submittedForm) markFormClean(submittedForm);
  return body;
}

async function softApi(path, fallback = [], label = path, options = {}) {
  try { return await api(path, options); }
  catch (error) {
    // Cancellation belongs to the superseded page load. It is not an authority
    // failure and must never leak into the next route as Partial data.
    if (error?.name === 'AbortError') throw error;
    // Authentication is a page-level authority failure, not a degradable widget failure.
    // Let loadPage() own the redirect so an expired session can never masquerade as
    // healthy empty/partial data.
    if (error.sessionExpired || error.status === 401) throw error;
    state.degradedRequests.push({label, path, message:error.message, status:error.status || 0});
    return fallback;
  }
}
function handleSessionExpired() {
  if(state.sessionRedirectPending)return;
  state.sessionRedirectPending=true;
  const sessionState=$('#session-state');if(sessionState)sessionState.textContent='Session expired';
  toast('Your session expired. Sign in again to continue.','error');
  setTimeout(()=>{location.href=`/auth/login?return=${encodeURIComponent(location.pathname+location.hash)}`;},600);
}

function renderDegradedState() {
  const banner=$('#page-degraded-banner'); if(!banner)return;
  if(!state.degradedRequests.length){banner.hidden=true;banner.innerHTML='';return;}
  const unique=[]; const seen=new Set();
  for(const item of state.degradedRequests){const key=`${item.path}:${item.status}`;if(seen.has(key))continue;seen.add(key);unique.push(item);}
  banner.hidden=false;
  banner.innerHTML=`<strong>Partial data:</strong> ${unique.length} source${unique.length===1?' is':'s are'} temporarily unavailable. Healthy widgets remain usable. <details><summary>Show unavailable sources</summary><ul>${unique.map(item=>`<li><span class="technical">${esc(item.label)}</span> — ${esc(item.message)}</li>`).join('')}</ul></details>`;
}

async function apiBlob(path, options = {}) {
  const request = {...options, headers: {...(options.headers || {})}};
  if (request.body !== undefined && typeof request.body !== 'string') { request.headers['Content-Type']='application/json'; request.body=JSON.stringify(request.body); }
  const response = await fetch(path, request);
  if (!response.ok) {
    const contentType=response.headers.get('content-type')||'';
    const body=contentType.includes('application/json')?await response.json():await response.text();
    const error=new Error(body?.error?.message||body?.message||(typeof body==='string'?body:`HTTP ${response.status}`));
    error.status=response.status;error.code=body?.error?.code||`HTTP_${response.status}`;
    if(response.status===401&&path.startsWith('/api/')){error.sessionExpired=true;handleSessionExpired();}
    throw error;
  }
  return {blob:await response.blob(), digest:response.headers.get('x-support-bundle-digest')||'', redactions:response.headers.get('x-support-bundle-redactions')||'0', disposition:response.headers.get('content-disposition')||''};
}

function bytes(value){ const n=Number(value||0); if(!Number.isFinite(n)||n<=0)return '0 B'; const units=['B','KiB','MiB','GiB','TiB']; let x=n,i=0; while(x>=1024&&i<units.length-1){x/=1024;i++;} return `${x>=10||i===0?x.toFixed(0):x.toFixed(1)} ${units[i]}`; }

function toast(message, type = 'success') {
  const node = document.createElement('div');
  node.className = `toast ${type}`;
  node.setAttribute('role', type === 'error' ? 'alert' : 'status');
  node.innerHTML = `<span>${esc(message)}</span><button type="button" class="toast-close icon-button" aria-label="Close"><svg aria-hidden="true" class="control-icon"><use href="#icon-close"></use></svg></button>`;
  node.querySelector('button').onclick = () => node.remove();
  $('#toast-region').append(node);
  if (type !== 'error') setTimeout(() => node.remove(), 5200);
}

function confirmAction(title, message, danger = false) {
  return new Promise(resolve => {
    const dialog = $('#confirm-dialog');
    $('#confirm-title').textContent = title;
    $('#confirm-message').textContent = message;
    $('#confirm-accept').className = danger ? 'danger' : 'primary';
    dialog.returnValue = '';
    dialog.onclose = () => resolve(dialog.returnValue === 'confirm');
    dialog.showModal();
  });
}

function showDetails(title, html) {
  const dialog=$('#detail-dialog');
  $('#detail-title').textContent = title;
  $('#detail-content').innerHTML = html;
  applyAccessMode(dialog);
  dialog.showModal();
}

function sortDataTable(table, index, type, direction, persist = true) {
  if(!table || !Number.isInteger(index) || index < 0 || !['ascending','descending'].includes(direction))return false;
  const header=table.tHead?.rows?.[0]?.cells?.[index];
  if(!header || !header.hasAttribute('aria-sort'))return false;
  $$('thead th[aria-sort]',table).forEach(cell=>{cell.setAttribute('aria-sort','none');const indicator=cell.querySelector('.sort-indicator');if(indicator)indicator.textContent='↕';});
  header.setAttribute('aria-sort',direction);
  const indicator=header.querySelector('.sort-indicator');if(indicator)indicator.textContent=direction==='ascending'?'↑':'↓';
  const body=table.tBodies[0];
  if(!body)return false;
  const rows=[...body.rows];
  rows.forEach((row,originalIndex)=>{if(row.dataset.originalOrder===undefined||row.dataset.originalOrder==='')row.dataset.originalOrder=String(originalIndex);});
  const normalized=(row)=>{
    const cell=row.cells[index];
    const raw=(cell?.dataset.sortValue ?? cell?.textContent ?? '').trim();
    if(!raw)return {missing:true,value:''};
    if(type==='numeric'){const value=Number(raw.replace(/[^0-9+-.]/g,''));return {missing:Number.isNaN(value),value};}
    if(type==='timestamp'){const value=Date.parse(raw);return {missing:Number.isNaN(value),value};}
    return {missing:false,value:raw};
  };
  rows.sort((a,b)=>{
    const av=normalized(a),bv=normalized(b);
    if(av.missing!==bv.missing)return av.missing?1:-1;
    let result=0;
    if(!av.missing){result=type==='text'?String(av.value).localeCompare(String(bv.value),state.locale==='fa'?'fa':'en',{numeric:true,sensitivity:'base'}):av.value-bv.value;}
    if(result===0)return Number(a.dataset.originalOrder)-Number(b.dataset.originalOrder);
    return direction==='ascending'?result:-result;
  });
  rows.forEach(row=>body.append(row));
  if(persist && table.dataset.tableKey)state.tableSortPreferences[table.dataset.tableKey]={index,type,direction};
  return true;
}
function restoreDataTableSortPreferences(root=document) {
  $$('table.data-table[data-table-key]',root).forEach(table=>{
    const preference=state.tableSortPreferences[table.dataset.tableKey];
    if(!preference)return;
    if(!sortDataTable(table,Number(preference.index),preference.type||'text',preference.direction,false))delete state.tableSortPreferences[table.dataset.tableKey];
  });
}

document.addEventListener('click', event => {
  const retry=event.target.closest('[data-retry-current]');
  if(retry){ event.preventDefault(); $('#refresh-current')?.click(); return; }
  const sortButton=event.target.closest('[data-table-sort-index]');
  if(!sortButton)return;
  event.preventDefault();
  const table=sortButton.closest('table');
  const header=sortButton.closest('th');
  const index=Number(sortButton.dataset.tableSortIndex);
  const type=sortButton.dataset.sortType||'text';
  const current=header.getAttribute('aria-sort');
  const direction=current==='ascending'?'descending':'ascending';
  sortDataTable(table,index,type,direction,true);
});

document.addEventListener('click', async event => {
  const button=event.target.closest('[data-operation-evidence-payload]');
  if(!button)return;
  event.preventDefault();
  try{
    const payload=await api(`/api/v1/operations/${button.dataset.operationId}/evidence/${button.dataset.operationEvidencePayload}/payload`);
    const rendered=typeof payload==='string'?payload:JSON.stringify(payload,null,2);
    showDetails('Step evidence payload',`<div class="resource-details">${detailRow('Operation',button.dataset.operationId,true)}${detailRow('Evidence',button.dataset.operationEvidencePayload,true)}</div><pre class="technical" dir="ltr">${esc(rendered)}</pre>`);
  }catch(error){toast(error.message,'error');}
});

function askFields(title, fields, submitLabel = 'Continue') {
  return new Promise(resolve => {
    const dialog = $('#detail-dialog');
    $('#detail-title').textContent = title;
    $('#detail-content').innerHTML = `<div class="form-stack">${fields.map(field => `<label><span>${esc(field.label)}</span>${field.type === 'select' ? `<select data-field="${esc(field.name)}">${field.options.map(option => `<option value="${esc(option.value)}"${String(option.value) === String(field.value) ? ' selected' : ''}>${esc(option.label)}</option>`).join('')}</select>` : `<input data-field="${esc(field.name)}" type="${esc(field.type || 'text')}" value="${esc(field.value ?? '')}" ${field.min !== undefined ? `min="${esc(field.min)}"` : ''} ${field.max !== undefined ? `max="${esc(field.max)}"` : ''} required>`}</label>`).join('')}<div class="dialog-actions"><button type="button" class="secondary" data-dialog-cancel>Cancel</button><button type="button" class="primary" data-dialog-submit>${esc(submitLabel)}</button></div></div>`;
    const cancel = $('[data-dialog-cancel]', dialog);
    const submit = $('[data-dialog-submit]', dialog);
    const close = value => { dialog.close(); resolve(value); };
    cancel.onclick = () => close(null);
    submit.onclick = () => {
      const values = {};
      let valid = true;
      $$('[data-field]', dialog).forEach(input => { if (!input.reportValidity()) valid = false; values[input.dataset.field] = input.type === 'number' ? Number(input.value) : input.value.trim(); });
      if (valid) close(values);
    };
    dialog.showModal();
  });
}

function clusterRecordById(clusterId) {
  return state.clusters.map(row=>row.cluster||row).find(item=>item.id===clusterId);
}

function eligibleRecoveryCheckpoints(projectId, clusterId) {
  const cluster=clusterRecordById(clusterId);
  if(!cluster || !cluster.inventoryDigest) return [];
  const now=Date.now();
  return state.recoveryCheckpoints
    .filter(item=>item.projectId===projectId&&item.clusterId===clusterId&&item.state==='VERIFIED'&&item.inventoryDigest===cluster.inventoryDigest&&new Date(item.expiresAt).getTime()>now)
    .sort((a,b)=>new Date(b.completedAt)-new Date(a.completedAt));
}

async function chooseDestructiveRecoveryCheckpoint(title, projectId, clusterId) {
  const eligible=eligibleRecoveryCheckpoints(projectId,clusterId);
  if(!eligible.length){toast('Register a VERIFIED recovery checkpoint for the current cluster inventory before this destructive action.','error');return null;}
  const values=await askFields(title,[{name:'recoveryCheckpointId',label:'Recovery checkpoint',type:'select',value:eligible[0].id,options:eligible.map(item=>({value:item.id,label:`${item.provider} · ${item.reference} · expires ${formatDate(item.expiresAt)}`}))}],'Bind recovery & continue');
  return values?.recoveryCheckpointId||null;
}

function localDateTimeValue(date) {
  const d=new Date(date.getTime()-date.getTimezoneOffset()*60000);
  return d.toISOString().slice(0,16);
}

function setOptions(select, items, valueFn, labelFn, emptyLabel = 'No eligible options') {
  const previous = select.value;
  select.innerHTML = items.length ? items.map(item => `<option value="${esc(valueFn(item))}">${esc(labelFn(item))}</option>`).join('') : `<option value="">${esc(emptyLabel)}</option>`;
  if (items.some(item => String(valueFn(item)) === previous)) select.value = previous;
  select.disabled = items.length === 0;
}

function prerequisite(element, ok, message, page, action) {
  element.hidden = ok;
  if (!ok) element.innerHTML = `${esc(message)} <button class="link-button" type="button" data-navigate="${esc(page)}">${esc(action)}</button>`;
}

function renderPlanChanges(plan = []) {
  if (!plan.length) return '<p class="inline-summary">No plan changes are available yet. The connected agent may still be planning.</p>';
  return `<div class="timeline">${plan.map(change => `<div class="timeline-step ${change.action === 'NOOP' ? 'success' : ''}"><span class="timeline-dot">${change.action === 'NOOP' ? '✓' : '•'}</span><div><h4>${esc(change.action)} · ${esc(change.resource)}</h4><p>${esc(change.reason || 'Digest comparison')}</p></div></div>`).join('')}</div>`;
}

function renderPlanImpact(impact = {}) {
  if (!impact || !impact.digest) return '<div class="warning-banner"><strong>Impact analysis required</strong><br>This plan is legacy, pending, or was created before API/capacity/disruption evidence was available. Revalidate before approval.</div>';
  const capacity = impact.capacity || {};
  const disruption = impact.disruption || {};
  const capability = impact.capability || {};
  const capabilityRows = capability.checks || [];
  const compatibility = impact.compatibility || {};
  const compatibilityRows = compatibility.checks || [];
  const compatibilityTarget = compatibility.target || {};
  const apiRows = impact.api || [];
  const blockers = impact.blockers || [];
  const warnings = impact.warnings || [];
  const rollback = impact.rollback || {};
  const rollbackRows = rollback.resources || [];
  const evidence = impact.evidence || {};
  const evidenceRows = evidence.artifacts || [];
  const demand = capacity.demandDeltaKnown
    ? `${capacity.cpuRequestDeltaMilli || 0}m CPU · ${bytes(capacity.memoryRequestDeltaBytes || 0)} memory · ${capacity.podReplicaDelta || 0} pods`
    : `UNKNOWN${(capacity.unknownReasons || []).length ? ` · ${(capacity.unknownReasons || []).join('; ')}` : ''}`;
  const ceilings = `${capacity.cpuAllocatableCeilingMilli || 0}m CPU · ${bytes(capacity.memoryAllocatableCeilingBytes || 0)} memory · ${capacity.podsAllocatableCeiling || 0} pods`;
  const schemaPassed = apiRows.filter(row => row.schema?.status === 'PASS' && row.schema?.method === 'KUBE_APISERVER_DRY_RUN_STRICT').length;
  const compatibilityList = compatibilityRows.length ? `<div class="activity-list">${compatibilityRows.map(row => `<div class="activity-item"><div class="activity-main"><span class="check-icon">${row.status==='PASS'?'✓':'!'}</span><div><strong>${esc(row.constraint)} · ${esc(row.dimension)}</strong><small>Target: <span class="technical">${esc(row.target||'—')}</span> · Allowed: <span class="technical">${esc((row.allowed||[]).join(', ')||'—')}</span><br>${esc(row.authority||'—')}<br>${esc(row.message||'')}</small></div></div>${badge(row.status||'UNKNOWN')}</div>`).join('')}</div>` : '<p>No compatibility matrix decision was reported.</p>';
  const capabilityList = capabilityRows.length ? `<div class="activity-list">${capabilityRows.map(row => `<div class="activity-item"><div class="activity-main"><span class="check-icon">${row.status==='FAIL'?'!':row.status==='PASS'||row.status==='AVAILABLE'?'✓':'•'}</span><div><strong>${esc(row.domain)} · ${esc(row.key)}</strong><small>${esc(row.authority)} · ${row.required?'Required':'Context only'}<br>${esc(row.impact)}<br>${esc(row.detail)}${(row.evidence||[]).length?`<br>Evidence: ${(row.evidence||[]).map(item=>`<span class="technical">${esc(item)}</span>`).join(' · ')}`:''}</small></div></div>${badge(row.status||'UNKNOWN')}</div>`).join('')}</div>` : '<p>No capability preflight was reported.</p>';
  const apiList = apiRows.length ? `<div class="activity-list">${apiRows.map(row => { const schema=row.schema||{}; const schemaWarnings=schema.warnings||[]; return `<div class="activity-item"><div class="activity-main"><span class="check-icon">${row.severity === 'ERROR' ? '!' : row.severity === 'WARNING' ? '△' : '✓'}</span><div><strong class="technical">${esc(row.apiVersion)} · ${esc(row.kind)}</strong><small>${esc(row.discoveryStatus)} · ${esc(row.lifecycleStatus)}${row.customResource ? ` · CRD ${esc(row.crdName || 'unknown')}` : ''}<br>Schema: ${esc(schema.status||'MISSING')} · ${esc(schema.method||'not executed')} · HTTP ${esc(schema.httpStatus||0)}${schema.schemaIndexVersion?` · ${esc(schema.schemaIndexVersion)}`:''}${schemaWarnings.length?`<br>${schemaWarnings.map(w=>esc(w)).join('<br>')}`:''}<br>${esc(row.message || '')}</small></div></div>${badge(row.severity || 'INFO')}</div>`; }).join('')}</div>` : '<p>No API impact rows were reported.</p>';
  const quota = (capacity.quotaImpacts || []).length ? `<details><summary>Quota changes (${capacity.quotaImpacts.length})</summary><div class="activity-list">${capacity.quotaImpacts.map(row => `<div class="activity-item"><div class="activity-main"><span class="check-icon">•</span><div><strong>${esc(row.resource)}</strong><small>${esc(row.action)} · current ${esc(JSON.stringify(row.current || {}))} → desired ${esc(JSON.stringify(row.desired || {}))}</small></div></div></div>`).join('')}</div></details>` : '';
  const rollbackList = rollbackRows.length ? `<div class="activity-list">${rollbackRows.map(row => `<div class="activity-item"><div class="activity-main"><span class="check-icon">${row.status==='PASS'?'✓':'!'}</span><div><strong class="technical">${esc(row.resource)}</strong><small>${esc(row.changeAction||'UNKNOWN')} · ${esc(row.strategy||'UNKNOWN')}<br>Authorization: ${esc(row.authorizationStatus||'UNKNOWN')} · Dry-run: ${esc(row.dryRunStatus||'UNKNOWN')}${row.restoreObjectDigest?` · restore ${esc(shortDigest(row.restoreObjectDigest))}`:''}</small></div></div>${badge(row.status||'UNKNOWN')}</div>`).join('')}</div>` : '<p>No rollback feasibility evidence was reported.</p>';
  const evidenceList = evidenceRows.length ? `<div class="activity-list">${evidenceRows.map(row => `<div class="activity-item"><div class="activity-main"><span class="check-icon">${row.required?'✓':'•'}</span><div><strong>${esc(row.kind)}${row.resource?` · <span class="technical">${esc(row.resource)}</span>`:''}</strong><small>${esc(row.authority)} · ${esc(row.phase)} · retention ${esc(row.retentionDays||0)} days<br>Source: ${esc(row.sourceLocation||'—')}<br>Output: <span class="technical">${esc(row.outputLocation||'—')}</span></small></div></div>${badge(row.required?'REQUIRED':'OPTIONAL')}</div>`).join('')}</div>` : '<p>No evidence collection plan was reported.</p>';
  return `${blockers.length ? `<div class="warning-banner"><strong>Approval blockers</strong><ul>${blockers.map(item => `<li>${esc(item)}</li>`).join('')}</ul></div>` : ''}${warnings.length ? `<div class="prerequisite"><strong>Warnings</strong><ul>${warnings.map(item => `<li>${esc(item)}</li>`).join('')}</ul></div>` : ''}<div class="resource-details">${detailRow('Approval ready', impact.approvalReady ? 'YES' : 'NO')}${detailRow('Compatibility matrix',`${compatibility.status||'MISSING'} · ${compatibilityTarget.kubernetesVersion||'—'} × ${compatibilityTarget.architecture||'—'} × ${compatibilityTarget.distribution||'—'} × ${compatibilityTarget.provider||'—'}`)}${detailRow('Compatibility method',compatibility.method||'—')}${detailRow('Compatibility digest',shortDigest(compatibility.digest))}${detailRow('Capability preflight', `${capability.status||'MISSING'} · ${capabilityRows.filter(row=>row.required).filter(row=>row.status==='PASS').length}/${capabilityRows.filter(row=>row.required).length} required PASS`)}${detailRow('Capability method', capability.method||'—')}${detailRow('API checks', apiRows.length)}${detailRow('Strict schema dry-run', `${schemaPassed}/${apiRows.length} PASS`)}${detailRow('Rollback feasibility', `${rollback.status||'MISSING'} · ${rollbackRows.filter(row=>row.status==='PASS').length}/${rollbackRows.length} PASS`)}${detailRow('Evidence collection', `${evidence.status||'MISSING'} · ${evidence.requiredCount||0} required`)}${detailRow('Evidence method', evidence.method||'—')}${detailRow('Evidence retention', evidenceRows.length?`${evidenceRows[0]?.retentionDays||0} days`:'—')}${detailRow('Demand delta', demand)}${detailRow('Capacity ceiling', ceilings)}${detailRow('Ceiling check', capacity.ceilingCheck || 'UNKNOWN')}${detailRow('Current usage', capacity.currentUsageKnown ? 'Known' : 'UNKNOWN — allocatable is a ceiling, not free headroom')}${detailRow('Disruption', disruption.level || 'UNKNOWN')}${detailRow('Maintenance', disruption.maintenanceRecommendation || 'UNKNOWN')}${detailRow('Impact digest', shortDigest(impact.digest))}</div>${(disruption.reasons || []).length ? `<div class="prerequisite"><strong>Disruption reasons</strong><ul>${disruption.reasons.map(item => `<li>${esc(item)}</li>`).join('')}</ul></div>` : ''}${quota}<details><summary>Compatibility matrix (${compatibilityRows.length})</summary>${compatibilityList}</details><details><summary>Capability preflight (${capabilityRows.length})</summary>${capabilityList}</details><details><summary>API / CRD compatibility (${apiRows.length})</summary>${apiList}</details><details><summary>Rollback feasibility (${rollbackRows.length})</summary>${rollbackList}</details><details><summary>Evidence collection plan (${evidenceRows.length})</summary>${evidenceList}</details>`;
}

function renderCollectedBaselineEvidence(deployment = {}) {
  const rows = deployment.evidence || [];
  if (!rows.length) return '<p>No completion evidence has been collected yet.</p>';
  return `<div class="activity-list">${rows.map(row => `<div class="activity-item"><div class="activity-main"><span class="check-icon">✓</span><div><strong>${esc(row.kind)}${row.resource?` · <span class="technical">${esc(row.resource)}</span>`:''}</strong><small>${esc(row.authority)} · ${esc(shortDigest(row.digest))} · ${bytes(row.size||0)}<br>Collected: ${esc(formatDate(row.collectedAt))} · retain until ${esc(formatDate(row.retainUntil))}<br>${row.location?.startsWith('/api/')?`<a href="${esc(row.location)}" target="_blank" rel="noopener">Open sealed payload</a>`:`<span class="technical">${esc(row.location||'—')}</span>`}</small></div></div>${badge(row.required?'SEALED':'OPTIONAL')}</div>`).join('')}</div>`;
}

function planApprovalReady(deployment) {
  const compatibility=deployment?.planImpact?.compatibility||{}; const capability=deployment?.planImpact?.capability||{}; const capabilityRows=capability.checks||[]; const rows=deployment?.planImpact?.api||[]; const rollback=deployment?.planImpact?.rollback||{}; const rollbackRows=rollback.resources||[]; const evidence=deployment?.planImpact?.evidence||{}; const evidenceRows=evidence.artifacts||[]; return deployment?.planImpact?.digest && deployment.planImpact.approvalReady === true && deployment.planImpactDigest === deployment.planImpact.digest && compatibility.status==='PASS' && compatibility.method==='PLATFORM_COMPATIBILITY_MATRIX_V1' && compatibility.digest && compatibility.target?.kubernetesVersion && compatibility.target?.architecture && compatibility.target?.distribution && compatibility.target?.provider && capability.status==='PASS' && capability.method==='CLUSTER_CAPABILITY_PREFLIGHT_V1' && capabilityRows.some(row=>row.required) && capabilityRows.filter(row=>row.required).every(row=>row.status==='PASS') && rows.length>0 && rows.every(row=>row.schema?.status==='PASS' && row.schema?.method==='KUBE_APISERVER_DRY_RUN_STRICT') && rollback.status==='PASS' && rollback.method==='KUBE_ROLLBACK_FEASIBILITY_V1' && rollbackRows.length>0 && rollbackRows.every(row=>row.status==='PASS') && evidence.status==='PASS' && evidence.method==='BASELINE_EVIDENCE_COLLECTION_V1' && evidence.requiredCount>0 && evidenceRows.length===evidence.requiredCount && evidenceRows.every(row=>row.required===true && row.outputLocation && row.retentionDays>=30);
}

const pageTitles = {
  overview:{en:['Home','Overview'],fa:['خانه','نمای کلی']},
  installation:{en:['Infrastructure','Installation'],fa:['زیرساخت','نصب']},clusters:{en:['Infrastructure','Clusters'],fa:['زیرساخت','کلاسترها']},providers:{en:['Infrastructure','Providers'],fa:['زیرساخت','Providerها']},
  marketplace:{en:['Delivery','Marketplace'],fa:['تحویل','مارکت‌پلیس']},blueprints:{en:['Delivery','Blueprints'],fa:['تحویل','Blueprintها']},baselines:{en:['Delivery','Certified baselines'],fa:['تحویل','Baselineهای تأییدشده']},catalog:{en:['Delivery','Catalog releases'],fa:['تحویل','Releaseهای کاتالوگ']},validator:{en:['Delivery','Planning tools'],fa:['تحویل','ابزارهای برنامه‌ریزی']},
  fleet:{en:['Fleet','Fleet overview'],fa:['Fleet','نمای کلی Fleet']},verification:{en:['Fleet','Assurance'],fa:['Fleet','تضمین و تأیید']},
  operations:{en:['Operations','Activity & audit'],fa:['عملیات','فعالیت و ممیزی']},ai:{en:['Operations','AI Control Plane'],fa:['عملیات','کنترل‌پلین هوش مصنوعی']},lab:{en:['Operations','Lab & Certification'],fa:['عملیات','آزمایشگاه و گواهی']},notifications:{en:['Operations','Notifications'],fa:['عملیات','اعلان‌ها']},
  workspace:{en:['Administration','Organizations & projects'],fa:['مدیریت','سازمان‌ها و پروژه‌ها']},tenants:{en:['Administration','Tenants & branding'],fa:['مدیریت','Tenant و برندینگ']},services:{en:['Administration','Integrations & services'],fa:['مدیریت','Integration و سرویس‌ها']}
};
const sectionNavigation = {
  home:['overview'],
  infrastructure:['clusters','providers','installation'],
  delivery:['marketplace','blueprints','baselines','catalog','validator'],
  fleet:['fleet','verification'],
  operations:['operations','ai','lab','notifications'],
  administration:['workspace','tenants','services']
};
const sectionLabels = {
  home:{en:'Home',fa:'خانه'}, infrastructure:{en:'Infrastructure',fa:'زیرساخت'}, delivery:{en:'Delivery',fa:'تحویل'}, fleet:{en:'Fleet',fa:'Fleet'}, operations:{en:'Operations',fa:'عملیات'}, administration:{en:'Administration',fa:'مدیریت'}
};
function sectionForPage(page){
  return Object.entries(sectionNavigation).find(([,pages])=>pages.includes(page))?.[0] || 'home';
}
function updateNavigationState(){
  const section=sectionForPage(state.currentPage);
  $$('#primary-nav button[data-section]').forEach(button=>{
    const active=button.dataset.section===section;
    button.classList.toggle('active',active);
    if(active) button.setAttribute('aria-current',section==='home'?'page':'location'); else button.removeAttribute('aria-current');
    const label=sectionLabels[button.dataset.section]?.[state.locale==='fa'?'fa':'en'];
    const span=button.querySelector('span'); if(span&&label) span.textContent=label;
  });
  const sectionNav=$('#section-nav');
  if(sectionNav){
    sectionNav.hidden=section==='home';
    $$('#section-nav [data-section-nav]').forEach(group=>{group.hidden=group.dataset.sectionNav!==section;});
    $$('#section-nav button[data-page]').forEach(button=>{
      const page=button.dataset.page, active=page===state.currentPage;
      button.classList.toggle('active',active);
      if(active)button.setAttribute('aria-current','page');else button.removeAttribute('aria-current');
      const title=pageTitles[page]?.[state.locale==='fa'?'fa':'en']?.[1]; if(title)button.textContent=title;
    });
  }
}
function updateBreadcrumb() {
  const entry = pageTitles[state.currentPage] || pageTitles.overview;
  const [group, title] = entry[state.locale === 'fa' ? 'fa' : 'en'];
  $('#breadcrumb').textContent = `${group} / ${title}`;
  $('#page-title').textContent = title;
  document.title = `${title} · 4SO Platform Factory`;
  updateNavigationState();
}
async function navigate(page) {
  if (!pageTitles[page]) return false;
  if (page !== state.currentPage && hasUnsavedChanges()) {
    const discard = await confirmAction('Discard unsaved changes?', 'This page has unsaved form changes. Leave the page and discard them?', true);
    if (!discard) return false;
    clearDirtyForms();
  }
  state.currentPage = page;
  $$('.page').forEach(section => section.classList.toggle('active', section.id === page));
  updateNavigationState();
  setMobileNav(false);
  updateBreadcrumb();
  history.replaceState(null, '', `#${page}`);
  const loaded = await loadPage(page);
  if (!loaded || state.currentPage !== page) return false;
  const title=(pageTitles[page]||pageTitles.overview)[state.locale==='fa'?'fa':'en'][1];
  const announcer=$('#route-announcer');if(announcer)announcer.textContent=state.locale==='fa'?`صفحه ${title} بارگذاری شد`:`${title} page loaded`;
  $('#main-content').focus({preventScroll:true});
  window.scrollTo({top:0, behavior:'smooth'});
  return true;
}
document.addEventListener('click', event => {
  const target = event.target.closest('[data-navigate]');
  if (target) navigate(target.dataset.navigate);
});
$$('#primary-nav button[data-section]').forEach(button => button.onclick = () => navigate(button.dataset.sectionHome));
$$('#section-nav button[data-page]').forEach(button => button.onclick = () => navigate(button.dataset.page));
function mobileNavFocusable(){
  return $$('.sidebar a[href], .sidebar button:not([disabled]), .sidebar input:not([disabled]), .sidebar select:not([disabled]), .sidebar textarea:not([disabled]), .sidebar [tabindex]:not([tabindex="-1"])').filter(node=>!node.hidden);
}
function syncMobileNavAccessibility(open = $('.sidebar').classList.contains('open')){
  const sidebar=$('.sidebar');
  const mobile=window.matchMedia('(max-width: 900px)').matches;
  sidebar.inert = mobile && !open;
  sidebar.setAttribute('aria-hidden', mobile && !open ? 'true' : 'false');
}
function setMobileNav(open){
  const sidebar=$('.sidebar'),toggle=$('#mobile-nav-toggle'),scrim=$('#nav-scrim');
  sidebar.classList.toggle('open',open); toggle.setAttribute('aria-expanded',open?'true':'false');
  scrim.hidden=!open; document.body.classList.toggle('nav-open',open);
  syncMobileNavAccessibility(open);
  if(open){const first=mobileNavFocusable()[0];if(first)first.focus();}
}
window.addEventListener('resize',()=>syncMobileNavAccessibility());
$('#mobile-nav-toggle').onclick = () => setMobileNav(!$('.sidebar').classList.contains('open'));
$('#nav-scrim').onclick = () => { setMobileNav(false); $('#mobile-nav-toggle').focus(); };
syncMobileNavAccessibility(false);
document.addEventListener('keydown',event=>{
  if(!$('.sidebar').classList.contains('open'))return;
  if(event.key==='Escape'){event.preventDefault();setMobileNav(false);$('#mobile-nav-toggle').focus();return;}
  if(event.key!=='Tab')return;
  const focusable=mobileNavFocusable();if(!focusable.length)return;
  const first=focusable[0],last=focusable[focusable.length-1],active=document.activeElement;
  if(event.shiftKey&&(active===first||!$('.sidebar').contains(active))){event.preventDefault();last.focus();}
  else if(!event.shiftKey&&(active===last||!$('.sidebar').contains(active))){event.preventDefault();first.focus();}
});
$('#language-toggle').onclick = async () => {
  if(hasUnsavedChanges()&&!await confirmAction('Discard unsaved changes?', 'Changing the console language refreshes this page and will discard unsaved form changes.', true))return;
  clearDirtyForms();state.locale = state.locale === 'fa' ? 'en' : 'fa'; localStorage.setItem('platformLocale', state.locale); applyLocale(); await loadPage(state.currentPage);
};
$('#theme-toggle').onclick = toggleConsoleTheme;
$('#refresh-current').onclick = async () => {
  if(hasUnsavedChanges()&&!await confirmAction('Discard unsaved changes?', 'Refreshing from the authoritative API will discard unsaved form changes.', true))return;
  clearDirtyForms();await syncSessionAuthority({redirectOnUnauthorized:true});if(state.sessionRedirectPending)return;await loadPage(state.currentPage, true);
};
$('#logout').onclick = async () => { await fetch('/auth/logout', {method:'POST'}); location.href = '/auth/login'; };

async function authorityJSON(path) {
  const response=await fetch(path,{signal:new AbortController().signal,headers:{Accept:'application/json'}});
  const contentType=response.headers.get('content-type')||'';
  const body=contentType.includes('application/json')?await response.json():await response.text();
  if(!response.ok){
    const error=new Error(body?.error?.message||body?.message||(typeof body==='string'?body:`HTTP ${response.status}`));
    error.status=response.status;error.code=body?.error?.code||`HTTP_${response.status}`;
    throw error;
  }
  return body;
}

async function syncSessionAuthority({redirectOnUnauthorized=false} = {}) {
  if (state.sessionRefreshPromise) return state.sessionRefreshPromise;
  const previousCanOperate=canOperate();
  state.sessionRefreshPromise = (async () => {
    try {
      state.session = await authorityJSON('/auth/session');
      state.permissionContextReady=false;
      try{
        const context=await authorityJSON('/api/v1/access/context');
        state.accessContext=isPermissionContext(context)?context:null;
        state.permissionContextReady=!!state.accessContext;
      }catch(scopeError){
        if(scopeError?.status===401)throw scopeError;
        state.accessContext=null;
        state.permissionContextReady=false;
      }
      const label = state.session.name || state.session.email || state.session.sub || 'Signed in';
      const role = isLocalSession() ? 'local admin' : (sessionRoles().find(item => ['platform-admin','platform-operator','platform-viewer'].includes(item)) || 'read only');
      $('#session-state').textContent = `${label} · ${role}${state.permissionContextReady||canAdminister()?'':' · permission scope unavailable'}`;
      invalidateDestructiveConfirmationOnDemotion(previousCanOperate);
      applyAccessMode();
      return state.permissionContextReady||canAdminister();
    } catch (error) {
      state.session = null;
      state.accessContext = null;
      state.permissionContextReady=false;
      $('#session-state').textContent = 'Authentication unavailable';
      invalidateDestructiveConfirmationOnDemotion(previousCanOperate);
      applyAccessMode();
      if (redirectOnUnauthorized && error?.status === 401) handleSessionExpired();
      return false;
    } finally {
      state.sessionRefreshPromise = null;
    }
  })();
  return state.sessionRefreshPromise;
}

async function loadSession() { return syncSessionAuthority(); }

async function loadCore() {
  const [version, catalog, profiles, organizations, projects, clusters, imports, summary, operations, audit] = await Promise.all([
    api('/api/v1/version'), softApi('/api/v1/catalog/components',[],'catalog'), softApi('/api/v1/installations/profiles',[],'installation profiles'), softApi('/api/v1/organizations',[],'organizations'), softApi('/api/v1/projects',[],'projects'), softApi('/api/v1/clusters',[],'clusters'), softApi('/api/v1/cluster-imports',[],'cluster imports'), softApi('/api/v1/control-plane/summary',{},'control-plane summary'), softApi('/api/v1/operations?limit=200',[],'operations'), softApi('/api/v1/audit-events?limit=50',[],'audit')
  ]);
  Object.assign(state, {version, catalog, profiles, organizations, projects, clusters, imports, summary, operations, audit});
  $('#release-version').textContent=version.version||'unknown';
}

function latest(items) { return [...items].sort((a,b) => new Date(b.updatedAt || b.createdAt || 0) - new Date(a.updatedAt || a.createdAt || 0)); }
function operationLabel(operation) { return operation.kind || 'operation'; }

async function loadOverview() {
  try {
    await loadCore();
    const [deployments, verifications, closures, tenants, providerProfiles, providerClusters, services] = await Promise.all([
      softApi('/api/v1/baseline-deployments',[],'baseline deployments'), softApi('/api/v1/runtime-verifications',[],'runtime verifications'), softApi('/api/v1/runtime-closure-campaigns',[],'runtime closures'), softApi('/api/v1/tenants',[],'tenants'), softApi('/api/v1/provider-profiles',[],'provider profiles'), softApi('/api/v1/provider-clusters',[],'provider clusters'), softApi('/api/v1/system-services',[],'system services')
    ]);
    Object.assign(state, {baselineDeployments:deployments, verifications, closures, tenants, providerProfiles, providerClusters, services});
    const connected = state.clusters.filter(row => row.online).length;
    const failureSources=['baseline deployments','runtime verifications','runtime closures','tenants','provider profiles','provider clusters'];
    const failed = [...deployments, ...verifications, ...closures, ...tenants, ...providerProfiles, ...providerClusters].filter(item => String(item.state).includes('FAILED')).length;
    const organizationsUnavailable=sourceUnavailable('organizations');
    const projectsUnavailable=sourceUnavailable('projects');
    const clustersUnavailable=sourceUnavailable('clusters');
    const baselinesUnavailable=sourceUnavailable('baseline deployments');
    const failureAuthorityPartial=sourceUnavailable(failureSources);
    $('#overview-metrics').innerHTML = [
      ['Organizations', organizationsUnavailable?'—':state.organizations.length, organizationsUnavailable?'Organization authority unavailable':projectsUnavailable?'Project authority unavailable':`${state.projects.length} projects`],
      ['Connected clusters', clustersUnavailable?'—':connected, clustersUnavailable?'Cluster authority unavailable':`${state.clusters.length - connected} offline or pending`],
      ['Successful baselines', baselinesUnavailable?'—':deployments.filter(d => d.state === 'SUCCEEDED').length, baselinesUnavailable?'Baseline deployment authority unavailable':`${deployments.length} total deployments`],
      ['Needs attention', failureAuthorityPartial?(failed?`≥${failed}`:'—'):failed, failureAuthorityPartial?(failed?'Known failed workflows · partial authority':'Failure authorities unavailable'):(failed ? 'Open failed workflows' : 'No failed product workflow')]
    ].map(([label,value,detail]) => `<article class="metric-card"><strong>${esc(value)}</strong><span>${esc(label)}</span><small>${esc(detail)}</small></article>`).join('');

    const readinessCheck=(source,done,title,detail,page)=>({unknown:sourceUnavailable(source),done:!sourceUnavailable(source)&&done,title,detail,page});
    const checks = [
      readinessCheck('organizations',state.organizations.length > 0,'Create an organization','Ownership boundary for projects and entitlements','workspace'),
      readinessCheck('projects',state.projects.length > 0,'Create a project','Resource and operation isolation boundary','workspace'),
      readinessCheck('clusters',state.clusters.length > 0,'Connect a Kubernetes cluster','Outbound agent enrollment and fresh inventory','clusters'),
      readinessCheck('baseline deployments',deployments.some(d => d.state === 'SUCCEEDED'),'Apply the certified baseline','Explicit plan review and approval','baselines'),
      readinessCheck('runtime verifications',verifications.some(v => v.state === 'SUCCEEDED'),'Verify runtime health','Digest-pinned probe and report','verification'),
      readinessCheck('runtime closures',closures.some(c => c.state === 'SUCCEEDED'),'Close runtime evidence','Bind inventory, baseline and verification digests','verification')
    ];
    $('#journey-checklist').innerHTML = checks.map(check => `<div class="check-item ${check.done ? 'done' : check.unknown ? 'unknown' : ''}"><span class="check-icon">${check.done ? '✓' : check.unknown ? '?' : '○'}</span><div><strong>${esc(check.title)}</strong><small>${esc(check.detail)}${check.unknown?' Authority unavailable; retry before acting.':''}</small>${!check.done&&!check.unknown ? `<button type="button" class="link-button small-button" data-navigate="${check.page}">Continue</button>` : ''}</div></div>`).join('');
    const next = checks.find(check => !check.done&&!check.unknown);
    const unknownReadiness = checks.find(check => check.unknown);
    setIntrinsicDisabled($('#overview-next-action'), false);
    if(next){
      $('#overview-next-action').textContent = next.title;
      $('#overview-next-action').onclick = () => navigate(next.page);
    } else if(unknownReadiness){
      $('#overview-next-action').textContent = 'Retry unavailable readiness data';
      $('#overview-next-action').onclick = () => $('#refresh-current')?.click();
    } else {
      $('#overview-next-action').textContent = 'Review current operations';
      $('#overview-next-action').onclick = () => navigate('operations');
    }

    const attention = [];
    for (const item of latest([...deployments, ...verifications, ...closures, ...tenants, ...providerProfiles, ...providerClusters]).filter(item => String(item.state).includes('FAILED')).slice(0,6)) {
      attention.push(`<div class="activity-item"><div class="activity-main"><span class="check-icon">!</span><div><strong>${esc(item.displayName || item.baselineId || item.id)}</strong><small>${esc(item.lastError || 'Workflow failed and can be retried from its record.')}</small></div></div>${badge(item.state)}</div>`);
    }
    const offline = state.clusters.filter(row => !row.online).slice(0,3);
    for (const row of offline) attention.push(`<div class="activity-item"><div class="activity-main"><span class="check-icon">!</span><div><strong>${esc(row.cluster.displayName)}</strong><small>Cluster heartbeat or inventory is stale.</small></div></div>${badge('OFFLINE')}</div>`);
    const attentionPartial=sourceUnavailable([...failureSources,'clusters']);
    $('#attention-list').innerHTML = attention.length ? `${attentionPartial?'<div class="warning-banner"><strong>Attention is partial.</strong> One or more failure authorities are unavailable; additional issues may be hidden.</div>':''}${attention.join('')}` : attentionPartial ? unavailableState('Attention data') : emptyState('No urgent action', 'No failed workflow or offline connected cluster is currently reported.');

    const recent = latest([...state.operations.map(item => ({...item,_type:'operation'})), ...state.audit.map(item => ({...item,_type:'audit'}))]).slice(0,10);
    const activityPartial=sourceUnavailable(['operations','audit']);
    const recentMarkup=recent.length ? recent.map(item => `<div class="activity-item"><div class="activity-main"><span class="check-icon">${item._type === 'audit' ? 'A' : 'O'}</span><div><strong>${esc(item._type === 'audit' ? item.action : operationLabel(item))}</strong><small>${esc(item._type === 'audit' ? `${item.resourceType} · ${item.resourceId}` : `${item.targetRef} · ${item.state}`)}</small></div></div><time>${formatDate(item.occurredAt || item.updatedAt || item.createdAt)}</time></div>`).join('') : '';
    $('#overview-activity').innerHTML = recentMarkup ? `${activityPartial?'<div class="warning-banner"><strong>Recent activity is partial.</strong> One activity authority is temporarily unavailable.</div>':''}${recentMarkup}` : activityPartial ? unavailableState('Recent activity') : emptyState('No activity yet', 'Create an organization and start the first workflow.');
  } catch (error) {
    if(error?.name==='AbortError')throw error;
    const failed=errorState(error.message);
    $('#overview-metrics').innerHTML = failed;
    $('#journey-checklist').innerHTML = failed;
    $('#attention-list').innerHTML = failed;
    $('#overview-activity').innerHTML = failed;
    $('#overview-next-action').textContent = 'Overview unavailable';
    $('#overview-next-action').onclick = null;
    setIntrinsicDisabled($('#overview-next-action'), true);
  }
}

function organizationMembershipFor(organizationId) {
  return (state.accessContext?.memberships || []).find(item => item.organizationId === organizationId && item.state === 'ACTIVE');
}
function canManageOrganization(organizationId) {
  return scopeRoleAllows(effectiveOrganizationRole(organizationId),'admin');
}
async function loadOrganizationMemberships(organizationId) {
  const grid = $('#membership-grid');
  if (!organizationId) { state.organizationMemberships=[]; grid.innerHTML=emptyState('No organization selected','Select an organization to review access.'); return; }
  const allowed=canManageOrganization(organizationId);
  $('#membership-form').hidden=!allowed;
  if (!allowed) {
    const own=organizationMembershipFor(organizationId);
    state.organizationMemberships=own?[own]:[];
    grid.innerHTML=own?`<article class="resource-card"><div class="resource-header"><div><h3>${esc(own.subject)}</h3>${badge(own.role)}</div></div>${detailRow('State',badge(own.state))}${detailRow('Granted by',own.grantedBy,true)}<small>Membership administration requires organization-admin within this organization.</small></article>`:emptyState('No delegated access','This organization is visible through your authenticated access context.');
    return;
  }
  try {
    const rows=await api(`/api/v1/organizations/${encodeURIComponent(organizationId)}/memberships`);
    state.organizationMemberships=rows;
    grid.innerHTML=rows.length?rows.map(item=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.subject)}</h3><div class="resource-meta">${badge(item.role)} ${badge(item.state)}</div></div>${item.state==='ACTIVE'?`<button type="button" class="danger small-button" data-membership-revoke="${esc(item.subject)}" data-org="${esc(organizationId)}" data-revision="${item.revision}">Revoke</button>`:''}</div>${detailRow('Granted by',item.grantedBy,true)}${detailRow('Updated',formatDate(item.updatedAt))}</article>`).join(''):emptyState('No memberships','Grant the first organization-scoped membership.');
  } catch(error) { grid.innerHTML=errorState(error.message); }
}
function mayAdministerIdentityAuthority(){ return isLocalSession() || sessionRoles().includes('platform-admin'); }
function syncOIDCMappingScopeOptions(){
  const org=$('#oidc-organization'), project=$('#oidc-project'); if(!org||!project)return;
  const orgValue=org.value, projectValue=project.value;
  org.innerHTML='<option value="">No organization delegation</option>'+state.organizations.map(item=>`<option value="${esc(item.id)}">${esc(item.displayName)} · ${esc(item.name)}</option>`).join('');
  project.innerHTML='<option value="">No project delegation</option>'+state.projects.map(item=>`<option value="${esc(item.id)}">${esc(item.displayName)} · ${esc(item.name)}</option>`).join('');
  if([...org.options].some(x=>x.value===orgValue))org.value=orgValue;if([...project.options].some(x=>x.value===projectValue))project.value=projectValue;
}
async function loadIdentityAuthority(){
  const panel=$('#oidc-group-mapping-panel'); if(!panel)return;
  if(!mayAdministerIdentityAuthority()){panel.hidden=true;state.identityAuthority=null;state.oidcGroupMappings=[];return;}
  panel.hidden=false;
  try{
    const [authority,mappings]=await Promise.all([softApi('/api/v1/identity/authority',{},'identity authority'),softApi('/api/v1/identity/group-mappings',[],'group mappings')]);
    state.identityAuthority=authority;state.oidcGroupMappings=mappings;syncOIDCMappingScopeOptions();
    $('#oidc-group-authority-summary').innerHTML=`<strong>${esc(authority.groupMappingMethod)}</strong> · ${esc(authority.activeMappings)} active / ${esc(authority.totalMappings)} total · propagation ≤ ${esc(authority.groupPropagationSeconds)}s · realm roles ${authority.realmRolesAuthoritative?'authoritative':'ignored'} · audit ${authority.securityAuditFailClosed?'fail-closed':'best effort'}`;
    $('#oidc-group-mapping-grid').innerHTML=mappings.length?mappings.map(item=>`<article class="resource-card"><div class="resource-header"><div><h3 class="technical">${esc(item.group)}</h3><div class="resource-meta">${badge(item.productRole)} ${badge(item.state)}</div></div>${item.state==='ACTIVE'?`<button type="button" class="danger small-button" data-oidc-mapping-revoke="${esc(item.id)}">Revoke</button>`:''}</div><div class="resource-details">${detailRow('Organization role',item.organizationId?`${item.organizationRole} · ${item.organizationId}`:'—',true)}${detailRow('Project role',item.projectId?`${item.projectRole} · ${item.projectId}`:'—',true)}${detailRow('Revision',`r${item.revision}`)}${detailRow('Created by',item.createdBy,true)}${item.revokedBy?detailRow('Revoked by',item.revokedBy,true):''}</div></article>`).join(''):emptyState('No OIDC group mappings','Create an explicit group mapping before relying on OIDC identities for product access.');
  }catch(error){$('#oidc-group-authority-summary').innerHTML=errorState(error.message);$('#oidc-group-mapping-grid').innerHTML='';}
}

async function loadWorkspace() {
  try {
    const [organizations, projects, accessContext] = await Promise.all([softApi('/api/v1/organizations',[],'organizations'), softApi('/api/v1/projects',[],'projects'), softApi('/api/v1/access/context',{},'access context')]);
    const resolvedAccessContext=isPermissionContext(accessContext)?accessContext:state.accessContext;
    if(isPermissionContext(accessContext)){state.permissionContextReady=true;}
    Object.assign(state, {organizations, projects, accessContext:resolvedAccessContext});
    setOptions($('#project-organization'), organizations.filter(org=>canManageOrganization(org.id)), item => item.id, item => `${item.displayName} · ${item.name}`, 'No organization you can administer');
    setOptions($('#membership-organization'), organizations, item=>item.id, item=>`${item.displayName} · ${item.name}`, 'No accessible organization');
    setOptions($('#service-account-organization'), organizations, item=>item.id, item=>`${item.displayName} · ${item.name}`, 'No accessible organization'); syncServiceAccountProjects();
    const workspaceAccess=resolvedAccessContext||{};
    const memberships=workspaceAccess.allOrganizations?'All organizations':`${(workspaceAccess.memberships||[]).filter(item=>item.state==='ACTIVE').length} organization membership(s)`;
    $('#workspace-access-summary').innerHTML=`<strong>${esc(workspaceAccess.subject || state.session?.sub || 'authenticated subject')}</strong> · ${esc(workspaceAccess.globalRole || 'read-only')} · ${esc(memberships)}`;
    const cards = [];
    for (const org of organizations) {
      const children = projects.filter(project => project.organizationId === org.id);
      const edit=canManageOrganization(org.id)?`<button type="button" class="secondary small-button" data-org-edit="${esc(org.id)}" data-revision="${org.revision}">Edit</button>`:'<span class="approval-note">Read-only organization access</span>';
      cards.push(`<article class="resource-card"><div class="resource-header"><div><h3>${esc(org.displayName)}</h3><div class="resource-meta">${badge('organization')} ${organizationMembershipFor(org.id)?badge(organizationMembershipFor(org.id).role):''}</div></div>${edit}</div>${detailRow('Machine name', org.name, true)}${detailRow('Projects', children.length)}${detailRow('Created', formatDate(org.createdAt))}<div class="resource-details">${children.map(project => `<div class="inline-summary"><strong>${esc(project.displayName)}</strong><br><span class="technical">${esc(project.name)}</span></div>`).join('') || '<small>No projects yet.</small>'}</div></article>`);
    }
    $('#workspace-grid').innerHTML = cards.length ? cards.join('') : emptyState('No accessible organization', 'A platform administrator must create an organization or grant membership.');
    await loadOrganizationMemberships($('#membership-organization').value);
    await loadServiceAccounts($('#service-account-organization').value);
    await loadIdentityAuthority();
  } catch (error) { $('#workspace-grid').innerHTML = errorState(error.message); $('#membership-grid').innerHTML=errorState(error.message); }
}

$('#oidc-group-mapping-form').onsubmit=async event=>{
  event.preventDefault();if(!event.currentTarget.reportValidity())return;
  const body={group:$('#oidc-group-name').value.trim(),productRole:$('#oidc-product-role').value};
  if($('#oidc-organization').value){body.organizationId=$('#oidc-organization').value;body.organizationRole=$('#oidc-organization-role').value;}
  if($('#oidc-project').value){body.projectId=$('#oidc-project').value;body.projectRole=$('#oidc-project-role').value;}
  try{await api('/api/v1/identity/group-mappings',{method:'POST',body});$('#oidc-group-name').value='';toast('OIDC group mapping created.');await loadIdentityAuthority();}catch(error){toast(error.message,'error');}
};
$('#oidc-group-mapping-grid').onclick=async event=>{
  const button=event.target.closest('[data-oidc-mapping-revoke]');if(!button)return;const item=state.oidcGroupMappings.find(x=>x.id===button.dataset.oidcMappingRevoke);if(!item)return;
  if(!await confirmAction('Revoke OIDC group mapping',`Revoke ${item.group}? Current OIDC requests using only this mapping lose access immediately; browser group claims expire within the configured propagation window.`,true))return;
  try{await api(`/api/v1/identity/group-mappings/${item.id}/revoke`,{method:'POST',headers:{'If-Match':`"${item.revision}"`},body:{}});toast('OIDC group mapping revoked.');await loadIdentityAuthority();}catch(error){toast(error.message,'error');}
};

$('#organization-form').onsubmit = async event => {
  event.preventDefault();
  if (!event.currentTarget.reportValidity()) return;
  try {
    await api('/api/v1/organizations', {method:'POST', body:{name:$('#organization-name').value.trim(), displayName:$('#organization-display-name').value.trim()}});
    event.currentTarget.reset(); toast('Organization created.'); await loadWorkspace();
  } catch (error) { toast(error.message, 'error'); }
};
$('#project-form').onsubmit = async event => {
  event.preventDefault();
  if (!event.currentTarget.reportValidity()) return;
  try {
    await api('/api/v1/projects', {method:'POST', body:{organizationId:$('#project-organization').value, name:$('#project-name').value.trim(), displayName:$('#project-display-name').value.trim()}});
    $('#project-name').value = ''; $('#project-display-name').value = ''; toast('Project created.'); await loadWorkspace();
  } catch (error) { toast(error.message, 'error'); }
};
$('#membership-organization').onchange=()=>loadOrganizationMemberships($('#membership-organization').value);
$('#membership-form').onsubmit=async event=>{
  event.preventDefault(); if(!event.currentTarget.reportValidity()) return;
  const orgId=$('#membership-organization').value, subject=$('#membership-subject').value.trim(); if(!orgId||!subject)return;
  try { const existing=state.organizationMemberships.find(item=>item.subject===subject);const headers=existing?{'If-Match':`"${existing.revision}"`}:{'If-None-Match':'*'}; await api(`/api/v1/organizations/${encodeURIComponent(orgId)}/memberships/${encodeURIComponent(subject)}`,{method:'PUT',headers,body:{role:$('#membership-role').value}}); $('#membership-subject').value=''; toast('Organization access updated.'); await loadWorkspace(); }
  catch(error){toast(error.message,'error');}
};
$('#membership-grid').onclick=async event=>{
  const button=event.target.closest('[data-membership-revoke]'); if(!button)return;
  if(!await confirmAction('Revoke organization access',`Revoke ${button.dataset.membershipRevoke} from this organization?`,true))return;
  try { await api(`/api/v1/organizations/${encodeURIComponent(button.dataset.org)}/memberships/${encodeURIComponent(button.dataset.membershipRevoke)}/revoke`,{method:'POST',headers:{'If-Match':`"${button.dataset.revision}"`,'X-Confirm-Revoke':'revoke-organization-membership'}}); toast('Organization access revoked.'); await loadWorkspace(); }
  catch(error){toast(error.message,'error');}
};

function syncServiceAccountProjects() {
  const orgId=$('#service-account-organization').value;
  const projects=state.projects.filter(project=>project.organizationId===orgId);
  const select=$('#service-account-project');
  const previous=select.value;
  select.innerHTML=`<option value="">Organization-wide</option>${projects.map(project=>`<option value="${esc(project.id)}">${esc(project.displayName)} · ${esc(project.name)}</option>`).join('')}`;
  if([...select.options].some(option=>option.value===previous))select.value=previous;
}
function tokenEffectiveState(token){return token.state==='REVOKED'?'REVOKED':(new Date(token.expiresAt).getTime()<=Date.now()?'EXPIRED':'ACTIVE');}
function showOneTimeAPIToken(title,response){
  const value=response?.value||'';
  showDetails(title,`<div class="warning-banner"><strong>Copy this token now.</strong><p>The secret is returned only in this response and is not available from the API again.</p></div><pre id="one-time-api-token" class="technical" dir="ltr">${esc(value)}</pre><div class="dialog-actions"><button data-copy-one-time-token type="button" class="primary">Copy token</button></div><div class="resource-details">${detailRow('Token ID',response?.token?.id||'—',true)}${detailRow('Scope',response?.token?.projectId||response?.token?.organizationId||'—',true)}${detailRow('Expires',formatDate(response?.token?.expiresAt))}</div>`);
  const copy=$('[data-copy-one-time-token]'); if(copy)copy.onclick=async()=>{try{await navigator.clipboard.writeText(value);toast('API token copied.');}catch(_){toast('Clipboard access is unavailable.','error');}};
}
async function loadServiceAccounts(organizationId){
  const grid=$('#service-account-grid'),form=$('#service-account-form');
  if(!organizationId){state.serviceAccounts=[];state.apiTokens={};form.hidden=true;grid.innerHTML=emptyState('No organization selected','Select an organization to manage automation identities.');return;}
  const allowed=canManageOrganization(organizationId);
  form.hidden=!allowed;
  prerequisite($('#service-account-prerequisite'),allowed,'Automation identity management requires organization-admin for the selected organization.','workspace','Review organization access');
  if(!allowed){state.serviceAccounts=[];state.apiTokens={};grid.innerHTML=emptyState('Read-only automation access','Service accounts and token metadata are visible only to organization administrators.');return;}
  try{
    const rows=await api(`/api/v1/service-accounts?organizationId=${encodeURIComponent(organizationId)}`); state.serviceAccounts=rows; state.apiTokens={};
    await Promise.all(rows.map(async account=>{state.apiTokens[account.id]=await api(`/api/v1/service-accounts/${encodeURIComponent(account.id)}/tokens`);}));
    grid.innerHTML=rows.length?rows.map(account=>{
      const tokens=state.apiTokens[account.id]||[];
      const scope=account.projectId?`Project · ${account.projectId}`:'Organization-wide';
      const tokenRows=tokens.length?tokens.map(token=>{const effective=tokenEffectiveState(token);return `<div class="activity-item"><div class="activity-main"><span class="check-icon">⌁</span><div><strong class="technical">${esc(token.tokenPrefix)}</strong><small>${esc((token.permissions||[]).join(' + '))} · expires ${esc(formatDate(token.expiresAt))}</small></div></div><div class="resource-meta">${badge(effective)}${effective==='ACTIVE'?`<button type="button" class="secondary small-button" data-api-token-action="rotate" data-account-id="${esc(account.id)}" data-token-id="${esc(token.id)}" data-revision="${token.revision}">Rotate</button><button type="button" class="danger small-button" data-api-token-action="revoke" data-account-id="${esc(account.id)}" data-token-id="${esc(token.id)}" data-revision="${token.revision}">Revoke</button>`:''}</div></div>`}).join(''):'<small>No API tokens issued.</small>';
      return `<article class="resource-card"><div class="resource-header"><div><h3>${esc(account.displayName)}</h3><div class="resource-meta">${badge(account.state)} ${badge(account.productRole)}</div></div></div><div class="resource-details">${detailRow('Machine name',account.name,true)}${detailRow('Scope',scope,true)}${detailRow('Created by',account.createdBy,true)}</div><details><summary>API tokens · ${tokens.length}</summary><div class="activity-list">${tokenRows}</div></details><div class="resource-actions">${account.state==='ACTIVE'?`<button type="button" class="primary small-button" data-service-account-action="issue" data-id="${esc(account.id)}">Issue expiring token</button><button type="button" class="danger small-button" data-service-account-action="revoke" data-id="${esc(account.id)}" data-revision="${account.revision}">Revoke service account</button>`:''}</div></article>`;
    }).join(''):emptyState('No service accounts','Create a scoped automation identity. No token is issued until you explicitly request one.');
  }catch(error){grid.innerHTML=errorState(error.message);}
}
$('#service-account-organization').onchange=async()=>{syncServiceAccountProjects();await loadServiceAccounts($('#service-account-organization').value);};
$('#service-account-form').onsubmit=async event=>{
  event.preventDefault();if(!event.currentTarget.reportValidity())return;
  try{await api('/api/v1/service-accounts',{method:'POST',body:{organizationId:$('#service-account-organization').value,projectId:$('#service-account-project').value,name:$('#service-account-name').value.trim(),displayName:$('#service-account-display-name').value.trim(),productRole:$('#service-account-role').value}});$('#service-account-name').value='';$('#service-account-display-name').value='';toast('Service account created.');await loadServiceAccounts($('#service-account-organization').value);}catch(error){toast(error.message,'error');}
};
$('#service-account-grid').onclick=async event=>{
  const accountButton=event.target.closest('[data-service-account-action]');
  if(accountButton){const account=state.serviceAccounts.find(item=>item.id===accountButton.dataset.id);if(!account)return;const action=accountButton.dataset.serviceAccountAction;
    if(action==='issue'){const options=apiTokenPermissionProfiles(account);const values=await askFields('Issue API token',[{name:'hours',label:'Expires in hours',type:'number',value:24,min:1,max:8784},{name:'permission',label:'Permission profile',type:'select',options}], 'Issue token');if(!values)return;try{const response=await api(`/api/v1/service-accounts/${account.id}/tokens`,{method:'POST',headers:{'Idempotency-Key':idempotency('api-token-issue')},body:{expiresAt:new Date(Date.now()+Number(values.hours)*3600000).toISOString(),permissions:apiTokenPermissionsFromProfile(values.permission)}});showOneTimeAPIToken('API token issued',response);await loadServiceAccounts($('#service-account-organization').value);}catch(error){toast(error.message,'error');}return;}
    if(action==='revoke'){if(!await confirmAction('Revoke service account',`Revoke ${account.displayName} and immediately invalidate every active token?`,true))return;try{await api(`/api/v1/service-accounts/${account.id}/revoke`,{method:'POST',headers:{'If-Match':`"${account.revision}"`,'X-Confirm-Revoke':'revoke-service-account'}});toast('Service account revoked.');await loadServiceAccounts($('#service-account-organization').value);}catch(error){toast(error.message,'error');}return;}
  }
  const tokenButton=event.target.closest('[data-api-token-action]');if(!tokenButton)return;const account=state.serviceAccounts.find(item=>item.id===tokenButton.dataset.accountId);const token=(state.apiTokens[tokenButton.dataset.accountId]||[]).find(item=>item.id===tokenButton.dataset.tokenId);if(!account||!token)return;
  if(tokenButton.dataset.apiTokenAction==='revoke'){if(!await confirmAction('Revoke API token',`Immediately revoke ${token.tokenPrefix}?`,true))return;try{await api(`/api/v1/service-accounts/${account.id}/tokens/${token.id}/revoke`,{method:'POST',headers:{'If-Match':`"${token.revision}"`,'X-Confirm-Revoke':'revoke-api-token'}});toast('API token revoked.');await loadServiceAccounts($('#service-account-organization').value);}catch(error){toast(error.message,'error');}return;}
  const options=apiTokenPermissionProfiles(account);const values=await askFields('Rotate API token',[{name:'hours',label:'New expiry in hours',type:'number',value:24,min:1,max:8784},{name:'permission',label:'Permission profile',type:'select',options,value:apiTokenPermissionProfileValue(token.permissions)}],'Rotate token');if(!values)return;
  try{const response=await api(`/api/v1/service-accounts/${account.id}/tokens/${token.id}/rotate`,{method:'POST',headers:{'If-Match':`"${token.revision}"`,'X-Confirm-Rotate':'rotate-api-token','Idempotency-Key':idempotency('api-token-rotate')},body:{expiresAt:new Date(Date.now()+Number(values.hours)*3600000).toISOString(),permissions:apiTokenPermissionsFromProfile(values.permission)}});showOneTimeAPIToken('API token rotated',response);await loadServiceAccounts($('#service-account-organization').value);}catch(error){toast(error.message,'error');}
};

$('#workspace-grid').onclick = async event => {
  const button = event.target.closest('[data-org-edit]'); if (!button) return;
  const org = state.organizations.find(item => item.id === button.dataset.orgEdit); if (!org) return;
  const values = await askFields('Edit organization', [{name:'name',label:'Machine name',value:org.name},{name:'displayName',label:'Display name',value:org.displayName}], 'Save');
  if (!values) return;
  try { await api(`/api/v1/organizations/${org.id}`, {method:'PUT', headers:{'If-Match':`"${org.revision}"`}, body:values}); toast('Organization updated.'); await loadWorkspace(); } catch (error) { toast(error.message,'error'); }
};

const installationServiceDefinitions = {
  git:{title:'Git desired state',managed:'forgejo',fields:['url','credentialRef','organization','repository','webhookMode']},
  registry:{title:'OCI registry',managed:'zot',fields:['url','credentialRef']},
  database:{title:'PostgreSQL authority',managed:'cloudnative-pg',fields:['url','credentialRef','region']},
  objectStorage:{title:'Evidence and backup storage',managed:'local-evidence',fields:['url','credentialRef','bucket','prefix','region']},
  identity:{title:'Identity and SSO',managed:'keycloak',fields:['issuerUrl','clientId','credentialRef','adminEmail']}
};
const installationFieldLabels={url:'HTTPS endpoint',credentialRef:'Credential reference',organization:'Organization',repository:'Repository',webhookMode:'Webhook mode',region:'Region',bucket:'Bucket',prefix:'Prefix',issuerUrl:'OIDC issuer URL',clientId:'OIDC client ID',adminEmail:'Bootstrap administrator email'};
function installationProvider(id){return String(id||'').replace(/^managed-/,'').replace(/^external-/,'');}
function renderInstallationServices(){
  $('#installation-service-editor').innerHTML=Object.entries(installationServiceDefinitions).map(([kind,definition])=>{
    const integrations=state.installationIntegrations[kind]||[];
    const options=integrations.length?integrations.map(item=>`<option value="${esc(item.id)}" data-mode="${esc(item.mode)}" ${item.default?'selected':''}>${esc(item.id.replaceAll('-',' '))}</option>`).join(''):`<option value="managed-${esc(definition.managed)}" data-mode="managed-internal">Managed ${esc(definition.managed)}</option>`;
    const fields=definition.fields.map(name=>`<label data-installation-field="${esc(name)}"><span>${esc(installationFieldLabels[name])}</span><input data-input="${esc(name)}" ${['url','issuerUrl'].includes(name)?'type="url"':''} class="${['url','issuerUrl','credentialRef'].includes(name)?'technical':''}" ${['url','issuerUrl','credentialRef'].includes(name)?'dir="ltr"':''} placeholder="${name==='credentialRef'?'secret:// or external-secret://':''}"></label>`).join('');
    return `<article class="integration-card" data-installation-service="${esc(kind)}"><h3>${esc(definition.title)}</h3><label><span>Mode and provider</span><select data-input="integration">${options}</select></label><div class="integration-fields">${fields}</div></article>`;
  }).join('');
  $$('#installation-service-editor [data-input="integration"]').forEach(select=>{select.onchange=()=>syncInstallationService(select);syncInstallationService(select);});
}
function syncInstallationService(select){
  const card=select.closest('[data-installation-service]'),kind=card.dataset.installationService,mode=select.selectedOptions[0]?.dataset.mode||(select.value.startsWith('external-')?'external':'managed-internal');
  card.dataset.mode=mode;
  $$('[data-installation-field]',card).forEach(label=>{const name=label.dataset.installationField,managedIdentity=kind==='identity'&&name==='adminEmail'&&mode!=='external';label.hidden=mode!=='external'&&!managedIdentity;const input=$('input',label);input.required=(mode==='external'&&['url','credentialRef'].includes(name))||managedIdentity;});
}
function installationServiceSpec(kind){
  const card=$(`[data-installation-service="${kind}"]`),select=$('[data-input="integration"]',card),mode=card.dataset.mode||'managed-internal';
  const value=name=>$(`[data-input="${name}"]`,card)?.value.trim()||'';
  const spec={mode,provider:installationProvider(select.value)};
  if(mode==='external')for(const name of installationServiceDefinitions[kind].fields)if(value(name))spec[name]=value(name);
  if(mode!=='external'&&kind==='identity'&&value('adminEmail'))spec.adminEmail=value('adminEmail');
  return spec;
}
function selectedProfile() { return state.profiles.find(profile => profile.id === $('#installation-profile').value); }
function syncInstallationForm() {
  const profile = selectedProfile();
  if (profile) {
    $('#installation-profile-summary').innerHTML = `<strong>${esc(profile.displayName)}</strong><br>${esc(profile.description)}<br>Required nodes: ${profile.minNodes}${profile.recommendedNodes !== profile.minNodes ? ` · recommended ${profile.recommendedNodes}` : ''} · ${profile.production ? 'production' : 'evaluation'}`;
    const allowed = new Set(profile.supportedConnectivity || []);
    $$('#installation-connectivity option').forEach(option => option.disabled = allowed.size > 0 && !allowed.has(option.value));
    if (allowed.size && !allowed.has($('#installation-connectivity').value)) $('#installation-connectivity').value = [...allowed][0];
    if(profile.id==='evaluation-single-node')$('#installation-tls-mode').value='bootstrap-self-signed';
    if(profile.id==='integrated-enterprise')$('#installation-provider').value='existing-kubernetes';
  }
  const existingCluster=$('#installation-provider').value==='existing-kubernetes';
  $('#installation-nodes-field').hidden=existingCluster;
  $('#installation-ssh-user-field').hidden=existingCluster;
  $('#installation-nodes').required=!existingCluster;
  $('#certificate-ref-field').hidden = $('#installation-tls-mode').value !== 'external-certificate';
  $('#installation-certificate-ref').required=!$('#certificate-ref-field').hidden;
}
async function loadInstallation() {
  try {
    const [profiles,integrations]=await Promise.all([softApi('/api/v1/installations/profiles',[],'installation profiles'),softApi('/api/v1/installations/integrations',{},'installation integrations')]);
    state.profiles = profiles; state.installationIntegrations=integrations;
    setOptions($('#installation-profile'), state.profiles, item => item.id, item => `${item.displayName}${item.default ? ' · default' : ''}`);
    renderInstallationServices(); syncInstallationForm();
  } catch (error) { $('#installation-profile-summary').innerHTML = errorState(error.message); }
}
$('#installation-profile').onchange = syncInstallationForm;
$('#installation-connectivity').onchange = syncInstallationForm;
$('#installation-provider').onchange = syncInstallationForm;
$('#installation-tls-mode').onchange = syncInstallationForm;
$('#installation-reset').onclick = () => setTimeout(()=>{renderInstallationServices();syncInstallationForm();$('#installation-plan-panel').hidden=true;},0);
$('#installation-form').onsubmit = async event => {
  event.preventDefault(); if (!event.currentTarget.reportValidity()) return;
  const existingCluster=$('#installation-provider').value==='existing-kubernetes';
  const nodes = existingCluster?[]:$('#installation-nodes').value.split(/\r?\n|,/).map(value => value.trim()).filter(Boolean);
  const profile = selectedProfile();
  if (profile && !existingCluster && nodes.length < profile.minNodes) { toast(`This profile requires at least ${profile.minNodes} management nodes.`, 'error'); return; }
  const request = {
    profileId:$('#installation-profile').value, connectivity:$('#installation-connectivity').value,
    infrastructure:{provider:$('#installation-provider').value,existingCluster,nodeAddresses:nodes,credentialRef:$('#installation-credential-ref').value.trim(),sshUser:existingCluster?'':$('#installation-ssh-user').value.trim(),storageClass:$('#installation-storage-class').value.trim(),region:$('#installation-region').value.trim()},
    network:{publicEndpoint:$('#installation-endpoint').value.trim(),dnsZone:$('#installation-dns-zone').value.trim(),tlsMode:$('#installation-tls-mode').value,certificateRef:$('#installation-certificate-ref').value.trim()},
    services:{git:installationServiceSpec('git'),registry:installationServiceSpec('registry'),database:installationServiceSpec('database'),objectStorage:installationServiceSpec('objectStorage'),identity:installationServiceSpec('identity')},
    acceptRisk:$('#installation-accept-risk').checked
  };
  try {
    const plan = await api('/api/v1/installations/plans', {method:'POST', body:request});
    $('#installation-plan-panel').hidden = false;
    $('#installation-plan-summary').textContent = `${plan.status} · ${plan.executable ? 'executable' : 'not executable'} · ${plan.blockers?.length || 0} blockers`;
    $('#installation-plan-result').innerHTML = `${plan.blockers?.length ? `<div class="warning-banner"><strong>Blockers</strong><ul>${plan.blockers.map(item=>`<li>${esc(item)}</li>`).join('')}</ul></div>` : ''}${plan.warnings?.length ? `<div class="prerequisite"><strong>Warnings</strong><ul>${plan.warnings.map(item=>`<li>${esc(item)}</li>`).join('')}</ul></div>` : ''}<div class="two-column"><div><h3>Execution steps</h3><div class="timeline">${(plan.steps||[]).map(step=>`<div class="timeline-step"><span class="timeline-dot">${step.order}</span><div><h4>${esc(step.title)}</h4><p>${esc(step.stage)} · ${esc(step.executor)} · risk ${esc(step.risk)}</p></div></div>`).join('')}</div></div><div><h3>Customer actions</h3>${(plan.customerActions||[]).length?`<ul>${plan.customerActions.map(item=>`<li>${esc(item)}</li>`).join('')}</ul>`:'<p>No additional customer action.</p>'}<h3>Authority gate</h3><p>${esc(plan.authorityGate)}</p><details><summary>Technical identifiers</summary><div class="resource-details">${detailRow('Plan ID',plan.id,true)}${detailRow('Spec digest',plan.specDigest,true)}</div></details></div></div>`;
    toast('Installation plan created.');
  } catch (error) { toast(error.message,'error'); }
};


async function loadClusterMaintenanceAuthority(clusterId) {
  const generation=++state.maintenanceLoadGeneration;
  if (!clusterId) {
    state.clusterMaintenanceProfile=null; state.clusterMaintenanceWindows=[]; state.clusterMaintenanceRuns=[]; state.currentMaintenanceClusterId='';
    $('#maintenance-authority-summary').textContent='Connect a cluster first.';
    $('#maintenance-window-grid').innerHTML=emptyState('No maintenance windows','Connect a cluster and configure its environment profile first.');
    $('#maintenance-run-grid').innerHTML=emptyState('No maintenance runs','Create a bounded maintenance window first.');
    return;
  }
  let profile=null;
  try { profile=(await api(`/api/v1/clusters/${clusterId}/maintenance-profile`)).profile; } catch(error) { if(error.status!==404) throw error; }
  const [windowResult,runResult]=await Promise.all([softApi(`/api/v1/clusters/${clusterId}/maintenance-windows`,[],'maintenance windows'),softApi(`/api/v1/clusters/${clusterId}/maintenance-runs`,[],'maintenance runs')]);
  if(generation!==state.maintenanceLoadGeneration)return false;
  const profileForm=$('#maintenance-profile-form'),windowForm=$('#maintenance-window-form');
  const profileDirty=dirtyWithin(profileForm),windowDirty=dirtyWithin(windowForm);
  state.clusterMaintenanceProfile=profile; state.clusterMaintenanceWindows=windowResult.windows||[]; state.clusterMaintenanceRuns=runResult.runs||[]; state.currentMaintenanceClusterId=clusterId;
  if(!profileDirty){$('#maintenance-environment').value=profile?.environment||'DEVELOPMENT';$('#maintenance-default-timeout').value=profile?.defaultDrainTimeoutSeconds||300;markFormClean(profileForm);}
  if(!windowDirty){$('#maintenance-window-timeout').value=profile?.defaultDrainTimeoutSeconds||300;markFormClean(windowForm);}
  $('#maintenance-authority-summary').innerHTML=profile?`<strong>${esc(profile.environment)}</strong> · default drain ${esc(profile.defaultDrainTimeoutSeconds)}s · ${esc(state.clusterMaintenanceWindows.filter(w=>w.state==='ACTIVE').length)} active window(s) · inventory-bound approval · maxUnavailable=1`:'<strong>Profile required.</strong> Set the environment and default drain timeout before opening a maintenance window.';
  setIntrinsicDisabled($('#maintenance-window-form').querySelector('button[type="submit"]'), !profile);
  $('#maintenance-window-grid').innerHTML=state.clusterMaintenanceWindows.length?latest(state.clusterMaintenanceWindows).map(window=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(window.name)}</h3><div class="resource-meta">${badge(window.state)}${badge('maxUnavailable=1')}</div></div></div><div class="resource-details">${detailRow('Starts',formatDate(window.startsAt))}${detailRow('Ends',formatDate(window.endsAt))}${detailRow('Drain timeout',`${window.drainTimeoutSeconds}s`)}${detailRow('Created by',window.createdBy||'—')}${detailRow('Revision',window.revision)}</div><div class="resource-actions">${window.state==='ACTIVE'?`<button type="button" class="primary small-button" data-maintenance-window-action="run" data-id="${esc(window.id)}">Maintain node</button><button type="button" class="danger small-button" data-maintenance-window-action="cancel" data-id="${esc(window.id)}">Cancel window</button>`:''}</div></article>`).join(''):emptyState('No maintenance windows','Configure the environment profile, then create a bounded maintenance window.');
  $('#maintenance-run-grid').innerHTML=state.clusterMaintenanceRuns.length?latest(state.clusterMaintenanceRuns).map(run=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc((run.nodeNames||[]).join(', '))}</h3><div class="resource-meta">${badge(run.state)}${run.maxUnavailable?badge(`maxUnavailable=${run.maxUnavailable}`):''}</div></div></div><div class="resource-details">${detailRow('Operation',run.operationId||'—',true)}${detailRow('Inventory',shortDigest(run.inventoryDigest))}${detailRow('Window',run.windowId||'—',true)}${detailRow('Requested by',run.requestedBy||'—')}${detailRow('Approved by',run.approvedBy||'—')}${detailRow('Error',run.lastError||'—')}</div>${(run.results||[]).length?`<details><summary>Node results</summary><div class="activity-list">${run.results.map(row=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">${row.unCordoned||row.uncordoned?'✓':'!'}</span><div><strong class="technical">${esc(row.nodeName)}</strong><small>Cordon ${row.cordoned?'PASS':'NO'} · Drain ${row.drained?'PASS':'NO'} · Uncordon ${row.uncordoned?'PASS':'NO'} · evicted ${(row.evictedPods||[]).length} · PDB waits ${(row.pdbBlockedPods||[]).length}</small></div></div></div>`).join('')}</div></details>`:''}<div class="resource-actions">${run.state==='AWAITING_APPROVAL'?approvalControl(run,'Approve maintenance',`data-maintenance-run-action="approve" data-id="${esc(run.id)}" data-revision="${run.revision}"`):''}<button type="button" class="secondary small-button" data-maintenance-run-action="inspect" data-id="${esc(run.id)}">Inspect</button></div></article>`).join(''):emptyState('No maintenance runs','Start maintenance from an active window. Approval is required before the agent can claim work.');
  return true;
}

async function loadClusters() {
  try {
    const [projects, imports, clusters] = await Promise.all([softApi('/api/v1/projects',[],'projects'), softApi('/api/v1/cluster-imports',[],'cluster imports'), softApi('/api/v1/clusters',[],'clusters')]);
    Object.assign(state, {projects, imports, clusters});
    const connected=clusters.map(row=>row.cluster||row);
    setOptions($('#maintenance-cluster-select'), connected, item=>item.id, item=>`${item.displayName} · ${item.kubernetesVersion||'inventory pending'}`, 'Connect a cluster first');
    setOptions($('#cluster-project'), projects, item => item.id, item => `${item.displayName} · ${item.name}`, 'Create a project first');
    prerequisite($('#clusters-prerequisite'), projects.length > 0, 'A project is required before a cluster can be connected.', 'workspace', 'Create organization and project');
    setIntrinsicDisabled($('#cluster-import-form').querySelector('button[type="submit"]'), projects.length === 0);
    const clusterRows=clusters.map(row => {
      const cluster=row.cluster||row,inventory=row.inventory||{},readyNodes=(inventory.nodes||[]).filter(node=>node.ready).length,totalNodes=(inventory.nodes||[]).length;
      const actions=`<div class="row-actions"><button type="button" class="secondary small-button" data-cluster-action="inspect" data-id="${esc(cluster.id)}">Details</button>${canAdminister()&&cluster.connectionState!=='REVOKED'?`<button type="button" class="danger small-button" data-cluster-action="revoke" data-id="${esc(cluster.id)}">Revoke</button>`:''}</div>`;
      return tableRow([
        tableCell(`<span class="cell-title">${esc(cluster.displayName)}</span><span class="cell-meta technical">${esc(cluster.id)}</span>`),
        tableCell(`${badge(row.online?'ONLINE':'OFFLINE')} ${badge(cluster.connectionState||'connected')}`,'status-cell'),
        tableCell(`<span class="cell-title">${esc(row.target?.distributionIdentity||cluster.distribution||'Pending')}</span><span class="cell-meta technical">${esc(row.target?.provisioningMode||'import-existing')} · ${esc(cluster.kubernetesVersion||'version pending')}</span>`),
        tableCell(totalNodes?`${esc(readyNodes)}/${esc(totalNodes)} ready`:'Inventory pending','numeric'),
        tableCell(`<span class="cell-title technical">${esc(cluster.agentVersion||'Pending')}</span><span class="cell-meta">${inventory.apiDiscoveryComplete?'API complete':'API incomplete'} · ${inventory.crdDiscoveryComplete?'CRD complete':'CRD incomplete'}</span>`),
        tableCell(formatDate(cluster.lastSeenAt),'timestamp',cluster.lastSeenAt||''),
        tableCell(actions,'actions-cell')
      ]);
    });
    $('#cluster-grid').innerHTML=dataTable('Connected clusters',[{label:'Cluster'},{label:'State'},{label:'Platform'},{label:'Nodes',className:'numeric'},{label:'Agent / discovery'},{label:'Last seen',className:'timestamp'},{label:'Actions'}],clusterRows,'No connected clusters','Create and approve an enrollment request, then apply its manifest on the target cluster.',{source:'clusters'});
    $('#cluster-import-grid').innerHTML = imports.length ? latest(imports).map(item => `<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.displayName)}</h3><div class="resource-meta">${badge(item.state)}</div></div></div><div class="resource-details">${detailRow('Machine name',item.name,true)}${detailRow('Expires',formatDate(item.expiresAt))}${detailRow('Requested by',item.requestedBy || '—')}${detailRow('Revision',item.revision)}</div><div class="resource-actions">${item.state === 'PENDING_APPROVAL' ? approvalControl(item,'Approve',`data-import-action="approve" data-id="${esc(item.id)}" data-revision="${item.revision}"`) : ''}${['PENDING_APPROVAL','APPROVED'].includes(item.state)?`<button class="danger small-button" type="button" data-import-action="revoke" data-id="${esc(item.id)}" data-revision="${item.revision}">Cancel enrollment</button>`:''}<button class="secondary small-button" type="button" data-import-action="inspect" data-id="${esc(item.id)}">Inspect</button></div></article>`).join('') : emptyState('No enrollment requests', 'Use the connection form above to create the first request.');
    await loadClusterMaintenanceAuthority($('#maintenance-cluster-select').value);
  } catch (error) {
    $('#cluster-grid').innerHTML = errorState(error.message);
    $('#cluster-import-grid').innerHTML = errorState(error.message);
  }
}

$('#maintenance-cluster-select').onchange=async()=>{const select=$('#maintenance-cluster-select'),next=select.value,previous=state.currentMaintenanceClusterId,profileForm=$('#maintenance-profile-form'),windowForm=$('#maintenance-window-form');if((dirtyWithin(profileForm)||dirtyWithin(windowForm))&&!await confirmAction('Discard maintenance changes?','Switch clusters and discard unsaved maintenance profile/window changes?',true)){select.value=previous;return;}clearDirtyForms(profileForm);clearDirtyForms(windowForm);profileForm.reset();windowForm.reset();$('#maintenance-max-unavailable').value=1;try{await loadClusterMaintenanceAuthority(next);}catch(error){select.value=previous;toast(error.message,'error');if(previous)await loadClusterMaintenanceAuthority(previous);}};
$('#maintenance-profile-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const clusterId=$('#maintenance-cluster-select').value;if(!clusterId)return;try{const headers={};if(state.clusterMaintenanceProfile?.revision)headers['If-Match']=`"${state.clusterMaintenanceProfile.revision}"`;await api(`/api/v1/clusters/${clusterId}/maintenance-profile`,{method:'PUT',headers,body:{environment:$('#maintenance-environment').value,defaultDrainTimeoutSeconds:Number($('#maintenance-default-timeout').value)}});toast('Cluster environment profile saved.');await loadClusterMaintenanceAuthority(clusterId);}catch(error){toast(error.message,'error');}};
$('#maintenance-window-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const clusterId=$('#maintenance-cluster-select').value;if(!clusterId)return;try{await api(`/api/v1/clusters/${clusterId}/maintenance-windows`,{method:'POST',body:{name:$('#maintenance-window-name').value.trim(),startsAt:new Date($('#maintenance-window-start').value).toISOString(),endsAt:new Date($('#maintenance-window-end').value).toISOString(),maxUnavailable:1,drainTimeoutSeconds:Number($('#maintenance-window-timeout').value)}});toast('Maintenance window created.');event.currentTarget.reset();$('#maintenance-max-unavailable').value=1;$('#maintenance-window-timeout').value=state.clusterMaintenanceProfile?.defaultDrainTimeoutSeconds||300;await loadClusterMaintenanceAuthority(clusterId);}catch(error){toast(error.message,'error');}};
$('#maintenance-window-grid').onclick=async event=>{const button=event.target.closest('[data-maintenance-window-action]');if(!button)return;const clusterId=$('#maintenance-cluster-select').value,window=state.clusterMaintenanceWindows.find(row=>row.id===button.dataset.id);if(!window)return;if(button.dataset.maintenanceWindowAction==='cancel'){if(!await confirmAction('Cancel maintenance window',`Cancel ${window.name}? Existing active runs must finish first.`,true))return;try{await api(`/api/v1/clusters/${clusterId}/maintenance-windows/${window.id}/cancel`,{method:'POST',headers:{'If-Match':`"${window.revision}"`},body:{}});toast('Maintenance window cancelled.');await loadClusterMaintenanceAuthority(clusterId);}catch(error){toast(error.message,'error');}return;}const record=state.clusters.find(row=>(row.cluster||row).id===clusterId),ready=(record?.inventory?.nodes||[]).filter(n=>n.ready);if(!ready.length){toast('Current inventory has no Ready nodes.','error');return;}const values=await askFields('Run node maintenance',[{name:'nodeName',label:'Ready node',type:'select',value:ready[0].name,options:ready.map(n=>({value:n.name,label:`${n.name} · ${(n.roles||[]).join(', ')||'worker'}`}))}],'Request approval');if(!values)return;try{await api(`/api/v1/clusters/${clusterId}/maintenance-runs`,{method:'POST',headers:{'Idempotency-Key':idempotency('cluster-maintenance')},body:{windowId:window.id,nodeNames:[values.nodeName]}});toast('Maintenance run created and waiting for independent approval.');await loadClusterMaintenanceAuthority(clusterId);}catch(error){toast(error.message,'error');}};
$('#maintenance-run-grid').onclick=async event=>{const button=event.target.closest('[data-maintenance-run-action]');if(!button)return;const clusterId=$('#maintenance-cluster-select').value,run=state.clusterMaintenanceRuns.find(row=>row.id===button.dataset.id);if(!run)return;if(button.dataset.maintenanceRunAction==='inspect'){try{const record=await api(`/api/v1/clusters/${clusterId}/maintenance-runs/${run.id}`);showDetails('Cluster maintenance run',`<dl class="key-value"><dt>Authority</dt><dd class="technical">KUBERNETES_NODE_MAINTENANCE_V1</dd><dt>State</dt><dd>${badge(record.run.state)}</dd><dt>Nodes</dt><dd class="technical">${esc((record.run.nodeNames||[]).join(', '))}</dd><dt>Inventory digest</dt><dd class="technical">${esc(record.run.inventoryDigest)}</dd><dt>Window</dt><dd class="technical">${esc(record.run.windowId)}</dd><dt>Operation</dt><dd class="technical">${esc(record.run.operationId)}</dd><dt>Drain timeout</dt><dd>${esc(record.run.drainTimeoutSeconds)}s</dd><dt>Error</dt><dd>${esc(record.run.lastError||'—')}</dd></dl>`);}catch(error){toast(error.message,'error');}return;}if(!await confirmAction('Approve node maintenance',`Approve cordon, PDB-aware drain and uncordon for ${(run.nodeNames||[]).join(', ')}?`))return;try{await api(`/api/v1/clusters/${clusterId}/maintenance-runs/${run.id}/approve`,{method:'POST',headers:{'If-Match':`"${run.revision}"`},body:{}});toast('Maintenance approved and queued for the cluster agent.');await loadClusterMaintenanceAuthority(clusterId);}catch(error){toast(error.message,'error');}};

$('#cluster-import-form').onsubmit = async event => {
  event.preventDefault(); if (!event.currentTarget.reportValidity()) return;
  try {
    const body = await api('/api/v1/cluster-imports', {method:'POST', body:{projectId:$('#cluster-project').value,name:$('#cluster-name').value.trim(),displayName:$('#cluster-display-name').value.trim(),expiresInMinutes:Number($('#cluster-expiration').value)}});
    $('#cluster-enrollment-panel').hidden = false;
    $('#cluster-enrollment-status').textContent = `Request ${body.import.id} is ${body.import.state}. Approve it before applying the manifest.`;
    $('#cluster-manifest').textContent = body.manifest || '';
    $('#cluster-enrollment-panel').dataset.importId = body.import.id;
    toast('Cluster import request created.');
    await loadClusters();
  } catch (error) { toast(error.message,'error'); }
};
$('#copy-cluster-manifest').onclick = async () => { try { await navigator.clipboard.writeText($('#cluster-manifest').textContent); toast('Manifest copied.'); } catch (_) { toast('Clipboard access is unavailable.','error'); } };
$('#cluster-import-grid').onclick = async event => {
  const button = event.target.closest('[data-import-action]'); if (!button) return;
  const item = state.imports.find(value => value.id === button.dataset.id);
  if (!item) return;
  if (button.dataset.importAction === 'inspect') {
    try {
      const record = await api(`/api/v1/cluster-imports/${item.id}`);
      showDetails('Cluster enrollment request', `<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(record.id)}</dd><dt>State</dt><dd>${badge(record.state)}</dd><dt>Project</dt><dd class="technical">${esc(record.projectId)}</dd><dt>Expires</dt><dd>${formatDate(record.expiresAt)}</dd><dt>Approved by</dt><dd>${esc(record.approvedBy || '—')}</dd><dt>Cluster</dt><dd class="technical">${esc(record.clusterId || 'Not claimed')}</dd></dl>`);
    } catch (error) { toast(error.message,'error'); }
    return;
  }
  if (button.dataset.importAction === 'revoke') {
    if (!await confirmAction('Cancel cluster enrollment', `Revoke ${item.displayName}? Its one-time manifest/token becomes unusable and the same cluster name can be enrolled again.`, true)) return;
    try {
      await api(`/api/v1/cluster-imports/${item.id}/revoke`, {method:'POST',headers:{'If-Match':`"${item.revision}"`,'X-Confirm-Revoke':'revoke-cluster-import'},body:{}});
      toast('Cluster enrollment cancelled.'); await loadClusters();
    } catch (error) { toast(error.message,'error'); }
    return;
  }
  const approved = await confirmAction('Approve cluster enrollment', `Approve ${item.displayName}? The manifest can then claim the cluster once before expiration.`);
  if (!approved) return;
  try {
    await api(`/api/v1/cluster-imports/${item.id}/approve`, {method:'POST',headers:{'If-Match':`"${item.revision}"`},body:{}});
    toast('Cluster enrollment approved.'); await loadClusters();
  } catch (error) { toast(error.message,'error'); }
};
$('#cluster-grid').onclick = async event => {
  const button = event.target.closest('[data-cluster-action]'); if (!button) return;
  const row = state.clusters.find(value => (value.cluster || value).id === button.dataset.id); if (!row) return;
  const cluster = row.cluster || row, inventory = row.inventory || {}, action = button.dataset.clusterAction;
  if (action === 'inspect') {
    try {
      const record = await api(`/api/v1/clusters/${cluster.id}`);
      const current = record.cluster || cluster, currentInventory = record.inventory || inventory, certificates = record.agentCertificates || [];
      const certificateRows = certificates.length ? `<div class="activity-list">${certificates.map(cert=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">${cert.state==='ACTIVE'?'✓':'×'}</span><div><strong class="technical">${esc(cert.fingerprint)}</strong><small>${esc(cert.serialNumber)} · expires ${formatDate(cert.notAfter)}</small></div></div><div class="resource-actions">${badge(cert.state)}${canAdminister()&&cert.state==='ACTIVE'?`<button type="button" class="danger small-button" data-agent-certificate-action="revoke" data-id="${esc(cert.id)}" data-revision="${cert.revision}">Revoke certificate</button>`:''}</div></div>`).join('')}</div>` : '<p>No client certificate has been issued yet. The bootstrap credential is only used to obtain the first certificate.</p>';
      showDetails(current.displayName, `<div class="detail-section"><h3>Connection</h3><dl class="key-value"><dt>ID</dt><dd class="technical">${esc(current.id)}</dd><dt>State</dt><dd>${badge(record.online ? 'ONLINE':'OFFLINE')}</dd><dt>Connection authority</dt><dd>${badge(current.connectionState || 'CONNECTED')}</dd><dt>Agent authentication</dt><dd>${badge(record.agentAuthentication || 'bootstrap-bearer')}</dd><dt>Distribution identity</dt><dd>${esc(record.target?.distributionIdentity || current.distribution || '—')}</dd><dt>Provisioning mode</dt><dd>${esc(record.target?.provisioningMode || 'import-existing')}</dd><dt>Infrastructure</dt><dd>${esc(record.target?.infrastructureProvider || 'existing')}</dd><dt>Observed legacy distribution</dt><dd>${esc(record.target?.legacyDistribution || current.distribution || '—')}</dd><dt>Kubernetes</dt><dd class="technical">${esc(current.kubernetesVersion || '—')}</dd><dt>Agent</dt><dd class="technical">${esc(current.agentVersion || '—')}</dd><dt>Last seen</dt><dd>${formatDate(current.lastSeenAt)}</dd></dl></div><div class="detail-section"><h3>Agent mTLS certificates</h3><p>Private keys stay on the managed cluster. The control plane stores certificate metadata and revocation state only.</p>${certificateRows}</div><div class="detail-section"><h3>Nodes</h3>${(currentInventory.nodes||[]).length ? `<div class="activity-list">${currentInventory.nodes.map(node=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">${node.ready?'✓':'!'}</span><div><strong class="technical">${esc(node.name)}</strong><small>${esc((node.roles||[]).join(', ') || 'worker')} · ${esc(node.os || '')} ${esc(node.architecture || '')}</small></div></div>${badge(node.ready?'READY':'NOT READY')}</div>`).join('')}</div>` : '<p>No node inventory reported.</p>'}</div><div class="detail-section"><h3>API / CRD discovery</h3><div class="resource-details">${detailRow('API discovery',currentInventory.apiDiscoveryComplete?'Complete':'Incomplete')}${detailRow('API resources',(currentInventory.apiResources||[]).length)}${detailRow('CRD discovery',currentInventory.crdDiscoveryComplete?'Complete':'Incomplete')}${detailRow('CRDs',(currentInventory.crds||[]).length)}</div>${!currentInventory.apiDiscoveryComplete||!currentInventory.crdDiscoveryComplete?'<div class="warning-banner">Planning impact cannot be approval-ready until API and CRD discovery evidence is complete.</div>':''}<details><summary>Discovered API resources</summary><pre class="code-block technical" dir="ltr">${esc((currentInventory.apiResources||[]).map(item=>`${item.apiVersion} ${item.kind} (${item.resource})`).join('\n')||'No API resource inventory')}</pre></details><details><summary>Discovered CRDs</summary><pre class="code-block technical" dir="ltr">${esc((currentInventory.crds||[]).map(item=>`${item.name} · ${(item.versions||[]).filter(v=>v.served).map(v=>v.name).join(', ')}`).join('\n')||'No CRD inventory')}</pre></details></div><div class="detail-section"><h3>Capabilities</h3><div class="resource-meta">${(current.capabilities||[]).map(cap=>`<span class="badge neutral">${esc(cap)}</span>`).join('') || 'None reported'}</div></div>`);
      $$('[data-agent-certificate-action="revoke"]', $('#detail-content')).forEach(certButton => {
        certButton.onclick = async () => {
          if (!await confirmAction('Revoke agent certificate', 'Immediately revoke this client certificate? The agent must use another active certificate or re-enroll before it can reconnect.', true)) return;
          try {
            await api(`/api/v1/clusters/${current.id}/agent-certificates/${certButton.dataset.id}/revoke`, {method:'POST', headers:{'If-Match':`"${certButton.dataset.revision}"`,'X-Confirm-Revoke':'revoke-agent-certificate'}, body:{}});
            $('#detail-dialog').close(); toast('Agent certificate revoked.'); await loadClusters();
          } catch (error) { toast(error.message,'error'); }
        };
      });
    } catch (error) { toast(error.message,'error'); }
    return;
  }
  if (action !== 'revoke' || !canAdminister()) return;
  if (!await confirmAction('Revoke cluster agent access', `Immediately invalidate the agent credential for ${cluster.displayName}? Historical inventory is retained, but a new enrollment request is required to reconnect.`, true)) return;
  try {
    await api(`/api/v1/clusters/${cluster.id}/revoke`, {method:'POST', headers:{'If-Match':`"${cluster.revision}"`,'X-Confirm-Revoke':'revoke-cluster-agent'}, body:{}});
    toast('Cluster agent credential revoked.'); await loadClusters();
  } catch (error) { toast(error.message,'error'); }
};

function renderTargetArchitectureSummary(model){
  const target=$('#target-architecture-summary');if(!target)return;
  const distributions=(model?.distributions||[]);
  const admitted=distributions.filter(item=>item.status==='SUPPORTED').map(item=>item.id);
  const previews=distributions.filter(item=>item.status==='RECOGNIZED_NOT_YET_ADMITTED').map(item=>item.id);
  const roadmap=model?.programRoadmap||{};
  const current=(roadmap.phases||[]).find(item=>item.id===roadmap.currentPhase);
  const resolver=model?.capabilityResolver||{};
  const trackCount=(roadmap.tracks||[]).length;
  target.innerHTML=`<strong>Target architecture</strong> · admitted <span class="technical">${esc(admitted.join(', ')||'none')}</span>${previews.length?` · preview only <span class="technical">${esc(previews.join(', '))}</span>`:''} · capability resolver <span class="technical">${esc(resolver.authority||'unavailable')}</span>${current?` · current product phase <strong>${esc(current.id)}</strong>`:''}${trackCount?` · <strong>${esc(trackCount)}</strong> cross-cutting product tracks`:''}`;
  const field=$('#provider-distributions');if(field&&admitted.length)field.placeholder=admitted.join(',');
}

async function loadProviders() {
  try {
    const [projects, clusterRows, profiles, providerClusters, recoveryCheckpoints, targetArchitecture] = await Promise.all([softApi('/api/v1/projects',[],'projects'),softApi('/api/v1/clusters',[],'clusters'),softApi('/api/v1/provider-profiles',[],'provider profiles'),softApi('/api/v1/provider-clusters',[],'provider clusters'),softApi('/api/v1/recovery-checkpoints',[],'recovery checkpoints'),softApi('/api/v1/target-architecture-model',{},'target architecture')]);
    Object.assign(state,{projects,clusters:clusterRows,providerProfiles:profiles,providerClusters,recoveryCheckpoints,targetArchitecture});
    renderTargetArchitectureSummary(targetArchitecture);
    setOptions($('#provider-project'),projects,item=>item.id,item=>`${item.displayName} · ${item.name}`,'Create a project first');
    const projectId = $('#provider-project').value;
    const management = clusterRows.map(row=>row.cluster||row).filter(cluster=>!projectId||cluster.projectId===projectId);
    setOptions($('#provider-management-cluster'),management,item=>item.id,item=>`${item.displayName} · ${item.kubernetesVersion || 'version pending'}`,'Connect a management cluster first');
    const visibleProfiles = profiles.filter(profile=>!projectId||profile.projectId===projectId);
    const readyProfiles = visibleProfiles.filter(profile=>profile.state==='READY');
    setOptions($('#provider-profile-select'),readyProfiles,item=>item.id,item=>`${item.displayName} · ${item.clusterClassName}`,'Verify a provider profile first');
    const selectedProfile=readyProfiles.find(item=>item.id===$('#provider-profile-select').value);
    if(selectedProfile){
      setOptions($('#provider-cluster-architecture'),selectedProfile.architectures||[],item=>item,item=>item,'No admitted architecture');
      setOptions($('#provider-cluster-distribution'),selectedProfile.distributionIdentities||selectedProfile.distributionProfiles||[],item=>item,item=>item,'No admitted distribution identity');
      if(!$('#provider-cluster-version').value) $('#provider-cluster-version').value=selectedProfile.defaultKubernetesVersion||'';
    }
    prerequisite($('#providers-prerequisite'),projects.length>0&&management.length>0,'A project and connected management cluster are required before provider verification.','clusters','Connect a cluster');
    setIntrinsicDisabled($('#provider-profile-form').querySelector('button[type="submit"]'), !projectId || !management.length);
    setIntrinsicDisabled($('#provider-cluster-form').querySelector('button[type="submit"]'), !readyProfiles.length);
    const profileRows=latest(visibleProfiles).map(profile=>tableRow([
      tableCell(`<span class="cell-title">${esc(profile.displayName)}</span><span class="cell-meta technical">${esc(profile.clusterClassName)} · worker ${esc(profile.workerClassName)}</span>`),
      tableCell(`${badge(profile.state)} ${badge(profile.adapter)}`,'status-cell'),
      tableCell(`<span class="cell-title technical">${esc(profile.defaultKubernetesVersion||'—')}</span><span class="cell-meta">${esc((profile.architectures||[]).join(', ')||'—')} · ${esc((profile.distributionProfiles||[]).join(', ')||'—')}</span>`),
      tableCell(`${esc(profile.maxWorkerReplicas||0)}`,'numeric'),
      tableCell(`<span class="technical">${esc(profile.managementClusterId||'—')}</span>`),
      tableCell(`<div class="row-actions">${profile.state==='FAILED'?`<button type="button" class="primary small-button" data-provider-profile-action="retry" data-id="${esc(profile.id)}" data-revision="${profile.revision}">Retry</button>`:''}<button type="button" class="secondary small-button" data-provider-profile-action="inspect" data-id="${esc(profile.id)}">Inspect</button></div>`,'actions-cell')
    ]));
    $('#provider-profile-grid').innerHTML=dataTable('Provider profiles',[{label:'Profile / ClusterClass'},{label:'State / adapter'},{label:'Runtime'},{label:'Max workers',className:'numeric'},{label:'Management cluster'},{label:'Actions'}],profileRows,'No provider profiles','Connect a Cluster API management cluster and verify its admitted ClusterClass.',{source:'provider profiles'});
    const visibleClusters = providerClusters.filter(cluster=>!projectId||cluster.projectId===projectId);
    const providerClusterRows=latest(visibleClusters).map(cluster=>{
      const actions=`<div class="row-actions">${['AWAITING_APPROVAL','DELETE_AWAITING_APPROVAL'].includes(cluster.state)?approvalControl(cluster,`Approve ${(cluster.pendingAction||'operation').toLowerCase()}`,`data-provider-cluster-action="approve" data-id="${esc(cluster.id)}"`):''}${cluster.state==='ACTIVE'?`<button type="button" class="secondary small-button" data-provider-cluster-action="scale" data-id="${esc(cluster.id)}">Scale</button><button type="button" class="secondary small-button" data-provider-cluster-action="upgrade" data-id="${esc(cluster.id)}">Upgrade</button><button type="button" class="danger small-button" data-provider-cluster-action="delete" data-id="${esc(cluster.id)}">Delete</button>`:''}${cluster.state==='FAILED'&&cluster.pendingAction!=='DELETE'?`<button type="button" class="primary small-button" data-provider-cluster-action="retry" data-id="${esc(cluster.id)}">Retry</button>`:''}${['FAILED','DELETE_AWAITING_APPROVAL','DELETE_QUEUED'].includes(cluster.state)?`<button type="button" class="danger small-button" data-provider-cluster-action="delete" data-id="${esc(cluster.id)}">${cluster.state==='FAILED'?'Delete':'Recover'}</button>`:''}<button type="button" class="secondary small-button" data-provider-cluster-action="inspect" data-id="${esc(cluster.id)}">Inspect</button></div>`;
      return tableRow([
        tableCell(`<span class="cell-title">${esc(cluster.displayName)}</span><span class="cell-meta technical">${esc(cluster.namespace)}/${esc(cluster.resourceName)}</span>`),
        tableCell(`${badge(cluster.state)} ${cluster.pendingAction?badge(cluster.pendingAction):''}`,'status-cell'),
        tableCell(`<span class="cell-title technical">${esc(cluster.desired?.kubernetesVersion||'—')}</span><span class="cell-meta">${esc(cluster.desired?.architecture||'—')} · ${esc(cluster.desired?.distribution||'—')}</span>`),
        tableCell(`CP ${esc(cluster.desired?.controlPlaneReplicas||0)} · W ${esc(cluster.desired?.workerReplicas||0)}`,'numeric'),
        tableCell(`<span class="cell-title">${esc(cluster.compatibility?.status||'MISSING')}</span><span class="cell-meta">${esc(cluster.compatibility?.method||'—')}</span>`),
        tableCell(actions,'actions-cell')
      ]);
    });
    $('#provider-cluster-grid').innerHTML=dataTable('Dedicated clusters',[{label:'Cluster / resource'},{label:'State'},{label:'Runtime'},{label:'Topology',className:'numeric'},{label:'Compatibility'},{label:'Actions'}],providerClusterRows,'No dedicated clusters','Verify a provider profile and create the first approval-bound cluster request.',{source:'provider clusters'});
  } catch (error) { $('#provider-profile-grid').innerHTML=errorState(error.message); $('#provider-cluster-grid').innerHTML=errorState(error.message); }
}
$('#provider-project').onchange=loadProviders;
$('#provider-profile-select').onchange=()=>{const profile=state.providerProfiles.find(item=>item.id===$('#provider-profile-select').value);if(!profile)return;setOptions($('#provider-cluster-architecture'),profile.architectures||[],item=>item,item=>item,'No admitted architecture');setOptions($('#provider-cluster-distribution'),profile.distributionIdentities||profile.distributionProfiles||[],item=>item,item=>item,'No admitted distribution identity');$('#provider-cluster-version').value=profile.defaultKubernetesVersion||$('#provider-cluster-version').value;};
$('#provider-profile-form').onsubmit=async event=>{
  event.preventDefault(); if(!event.currentTarget.reportValidity())return;
  const payload={projectId:$('#provider-project').value,managementClusterId:$('#provider-management-cluster').value,name:$('#provider-profile-name').value.trim(),displayName:$('#provider-profile-display-name').value.trim(),clusterClassName:$('#provider-cluster-class').value.trim(),workerClassName:$('#provider-worker-class').value.trim(),defaultKubernetesVersion:$('#provider-default-version').value.trim(),kubernetesSeries:$('#provider-series').value.split(',').map(v=>v.trim()).filter(Boolean),architectures:$('#provider-architectures').value.split(',').map(v=>v.trim().toLowerCase()).filter(Boolean),distributionProfiles:$('#provider-distributions').value.split(',').map(v=>v.trim().toLowerCase()).filter(Boolean),maxWorkerReplicas:Number($('#provider-max-workers').value)};
  try{await api('/api/v1/provider-profiles',{method:'POST',headers:{'Idempotency-Key':idempotency('provider-profile')},body:payload});toast('Provider profile verification queued.');event.currentTarget.reset();await loadProviders();}catch(error){toast(error.message,'error');}
};
$('#provider-cluster-form').onsubmit=async event=>{
  event.preventDefault();if(!event.currentTarget.reportValidity())return;
  const profile=state.providerProfiles.find(item=>item.id===$('#provider-profile-select').value);
  const payload={projectId:profile?.projectId||$('#provider-project').value,providerProfileId:$('#provider-profile-select').value,name:$('#provider-cluster-name').value.trim(),displayName:$('#provider-cluster-display-name').value.trim(),kubernetesVersion:$('#provider-cluster-version').value.trim(),architecture:$('#provider-cluster-architecture').value,distributionIdentity:$('#provider-cluster-distribution').value,controlPlaneReplicas:Number($('#provider-control-plane').value),workerReplicas:Number($('#provider-workers').value)};
  try{await api('/api/v1/provider-clusters',{method:'POST',headers:{'Idempotency-Key':idempotency('provider-cluster')},body:payload});toast('Dedicated cluster request created.');event.currentTarget.reset();await loadProviders();}catch(error){toast(error.message,'error');}
};
$('#provider-profile-grid').onclick=async event=>{
  const button=event.target.closest('[data-provider-profile-action]');if(!button)return;
  const profile=state.providerProfiles.find(item=>item.id===button.dataset.id);if(!profile)return;
  if(button.dataset.providerProfileAction==='inspect'){showDetails(profile.displayName,`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(profile.id)}</dd><dt>State</dt><dd>${badge(profile.state)}</dd><dt>ClusterClass</dt><dd class="technical">${esc(profile.clusterClassName)}</dd><dt>Worker class</dt><dd class="technical">${esc(profile.workerClassName)}</dd><dt>Architectures</dt><dd class="technical">${esc((profile.architectures||[]).join(', '))}</dd><dt>Distribution identities</dt><dd class="technical">${esc((profile.distributionIdentities||profile.distributionProfiles||[]).join(', '))}</dd><dt>Provisioning mode</dt><dd>${esc(profile.provisioningMode||'cluster-api')}</dd><dt>Infrastructure provider</dt><dd>${esc(profile.infrastructureProvider||'unspecified')}</dd><dt>Observed digest</dt><dd class="technical">${esc(profile.observedDigest||'—')}</dd><dt>Last error</dt><dd>${esc(profile.lastError||'—')}</dd></dl>`);return;}
  try{await api(`/api/v1/provider-profiles/${profile.id}/retry`,{method:'POST',headers:{'If-Match':`"${profile.revision}"`},body:{}});toast('Provider profile verification retried.');await loadProviders();}catch(error){toast(error.message,'error');}
};
$('#provider-cluster-grid').onclick=async event=>{
  const button=event.target.closest('[data-provider-cluster-action]');if(!button)return;
  const cluster=state.providerClusters.find(item=>item.id===button.dataset.id);if(!cluster)return;
  const action=button.dataset.providerClusterAction;
  if(action==='inspect'){showDetails(cluster.displayName,`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(cluster.id)}</dd><dt>State</dt><dd>${badge(cluster.state)}</dd><dt>Pending action</dt><dd>${esc(cluster.pendingAction||'—')}</dd><dt>Kubernetes</dt><dd class="technical">${esc(cluster.desired?.kubernetesVersion||'—')}</dd><dt>Architecture</dt><dd class="technical">${esc(cluster.desired?.architecture||'—')}</dd><dt>Distribution identity</dt><dd class="technical">${esc(cluster.desired?.distributionIdentity||cluster.desired?.distribution||'—')}</dd><dt>Provisioning mode</dt><dd>${esc(cluster.desired?.provisioningMode||'cluster-api')}</dd><dt>Infrastructure provider</dt><dd>${esc(cluster.desired?.infrastructureProvider||'unspecified')}</dd><dt>Compatibility</dt><dd>${badge(cluster.compatibility?.status||'MISSING')} <span class="technical">${esc(cluster.compatibility?.method||'—')}</span></dd><dt>Compatibility digest</dt><dd class="technical">${esc(cluster.compatibility?.digest||'—')}</dd><dt>Compatibility blockers</dt><dd>${esc((cluster.compatibility?.blockers||[]).join('; ')||'—')}</dd><dt>Control plane</dt><dd>${esc(cluster.desired?.controlPlaneReplicas)}</dd><dt>Workers</dt><dd>${esc(cluster.desired?.workerReplicas)}</dd><dt>Desired digest</dt><dd class="technical">${esc(cluster.desiredDigest)}</dd><dt>Observed digest</dt><dd class="technical">${esc(cluster.observedDigest||'—')}</dd><dt>Destructive operation</dt><dd class="technical">${esc(cluster.destructiveOperationId||'—')}</dd><dt>Error</dt><dd>${esc(cluster.lastError||'—')}</dd></dl>`);return;}
  let payload={},headers={'If-Match':`"${cluster.revision}"`};
  if(action==='scale'){const values=await askFields('Scale dedicated cluster',[{name:'controlPlaneReplicas',label:'Control-plane replicas',type:'select',value:cluster.desired?.controlPlaneReplicas,options:[{value:1,label:'1 · Non-HA'},{value:3,label:'3 · HA'}]},{name:'workerReplicas',label:'Worker replicas',type:'number',value:cluster.desired?.workerReplicas,min:1,max:500}],'Queue scale');if(!values)return;payload=values;}
  if(action==='upgrade'){const values=await askFields('Upgrade dedicated cluster',[{name:'kubernetesVersion',label:'Target Kubernetes version',value:cluster.desired?.kubernetesVersion}],'Queue upgrade');if(!values)return;payload=values;}
  if(action==='delete'){if(!await confirmAction('Delete dedicated cluster',`Delete ${cluster.displayName}? This is approval-bound and removes the provider Cluster resource.`,true))return;const checkpointId=await chooseDestructiveRecoveryCheckpoint('Bind recovery before provider delete',cluster.projectId,cluster.managementClusterId);if(!checkpointId)return;headers['X-Confirm-Delete']='delete-provider-cluster';payload={recoveryCheckpointId:checkpointId};}
  if(action==='approve'&&!await confirmAction('Approve provider operation',`Approve ${cluster.pendingAction||'operation'} for ${cluster.displayName}?`))return;
  try{await api(`/api/v1/provider-clusters/${cluster.id}/${action}`,{method:'POST',headers,body:payload});toast(`Provider cluster ${action} accepted.`);await loadProviders();}catch(error){toast(error.message,'error');}
};

async function loadMarketplace(){
  try{
    const [offers,clusterRows,installations,recommendations,recoveryCheckpoints]=await Promise.all([softApi('/api/v1/marketplace/offers',[],'marketplace offers'),softApi('/api/v1/clusters',[],'clusters'),softApi('/api/v1/marketplace/installations',[],'marketplace installations'),softApi('/api/v1/marketplace/recommendations',[],'recommendations'),softApi('/api/v1/recovery-checkpoints',[],'recovery checkpoints')]);
    Object.assign(state,{marketplaceOffers:offers,clusters:clusterRows,marketplaceInstallations:installations,recommendations,recoveryCheckpoints});
    const clusters=clusterRows.map(row=>row.cluster||row);
    setOptions($('#marketplace-cluster'),clusters,item=>item.id,item=>`${item.displayName} · ${item.kubernetesVersion||'version pending'}`,'Connect an eligible cluster first');
    setOptions($('#marketplace-offer'),offers,item=>`${item.id}@${item.version}`,item=>`${item.displayName} · ${item.version}`,'No published offers');
    prerequisite($('#marketplace-prerequisite'),clusters.length>0&&offers.length>0,'A connected cluster and published offer are required.','clusters','Connect a cluster');
    setIntrinsicDisabled($('#marketplace-install'), !clusters.length||!offers.length);
    setIntrinsicDisabled($('#marketplace-recommend'), !clusters.length||!offers.length);
    $('#marketplace-offer-grid').innerHTML=offers.length?offers.map(offer=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(offer.displayName)}</h3><div class="resource-meta">${badge(offer.category)}${badge(offer.risk)}</div></div></div><p>${esc(offer.description)}</p><div class="resource-details">${detailRow('Version',offer.version,true)}${detailRow('Scope',offer.scope)}${detailRow('Rollback',offer.rollback)}</div><div class="resource-meta">${(offer.capabilities||[]).map(cap=>`<span class="badge neutral">${esc(cap)}</span>`).join('')}</div></article>`).join(''):emptyState('No published offers','An offer is hidden until its complete runtime workflow is admitted.');
    $('#marketplace-installation-grid').innerHTML=installations.length?latest(installations).map(view=>{const d=view.installation||view,o=view.offer||offers.find(item=>item.id===d.sourceId&&item.version===d.sourceVersion)||{};return `<article class="resource-card"><div class="resource-header"><div><h3>${esc(o.displayName||d.sourceId)}</h3><div class="resource-meta">${badge(d.state)}${d.pendingAction?badge(d.pendingAction):''}</div></div></div><p>${technical(d.targetNamespace)} · ${technical(d.clusterId)}</p><div class="resource-details">${detailRow('Offer',`${d.sourceId}@${d.sourceVersion}`,true)}${detailRow('Desired',shortDigest(d.desiredDigest))}${detailRow('Observed',shortDigest(d.observedDigest))}${detailRow('Revision',d.revision)}</div>${d.lastError?`<div class="warning-banner">${esc(d.lastError)}</div>`:''}<details><summary>Planned changes</summary>${renderPlanChanges(d.plan)}</details><div class="resource-actions">${d.state==='AWAITING_APPROVAL'?approvalControl(d,'Approve install',`data-marketplace-action="approve" data-id="${esc(d.id)}"`):''}${d.state==='FAILED'&&d.pendingAction!=='ROLLBACK'?`<button type="button" class="primary small-button" data-marketplace-action="retry" data-id="${esc(d.id)}">Retry ${esc((d.pendingAction||'operation').toLowerCase())}</button>`:''}${['SUCCEEDED','FAILED','ROLLBACK_QUEUED'].includes(d.state)?`<button type="button" class="danger small-button" data-marketplace-action="uninstall" data-id="${esc(d.id)}">${d.state==='ROLLBACK_QUEUED'?'Refresh recovery':'Uninstall'}</button>`:''}<button type="button" class="secondary small-button" data-marketplace-action="inspect" data-id="${esc(d.id)}">Inspect</button></div></article>`}).join(''):emptyState('No marketplace installations','Select an offer and connected cluster to create the first plan.');
    $('#marketplace-recommendation-grid').innerHTML=recommendations.length?latest(recommendations).map(rec=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(rec.objective)}</h3><div class="resource-meta">${badge(rec.engine)}${rec.model?badge(rec.model):''}</div></div></div>${(rec.items||[]).length?`<div class="activity-list">${rec.items.map(item=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">${esc(item.score)}</span><div><strong>${esc(item.offerId)}@${esc(item.offerVersion)}</strong><small>${esc(item.reason)}</small></div></div></div>`).join('')}</div>`:'<p>No eligible uninstalled offer matched this objective.</p>'}<div class="resource-details">${detailRow('Context',shortDigest(rec.contextDigest))}${detailRow('Response',shortDigest(rec.responseDigest))}${detailRow('Created',formatDate(rec.createdAt))}</div></article>`).join(''):emptyState('No recommendations','Enter a concrete objective to request an advisory-only recommendation.');
  }catch(error){$('#marketplace-offer-grid').innerHTML=errorState(error.message);$('#marketplace-installation-grid').innerHTML=errorState(error.message);}
}
function marketplaceSelection(){const cluster=state.clusters.map(row=>row.cluster||row).find(item=>item.id===$('#marketplace-cluster').value);const [offerId,offerVersion]=($('#marketplace-offer').value||'').split('@');return {cluster,offerId,offerVersion};}
$('#marketplace-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const selected=marketplaceSelection();if(!selected.cluster||!selected.offerId)return;try{await api('/api/v1/marketplace/installations',{method:'POST',headers:{'Idempotency-Key':idempotency('marketplace-install')},body:{projectId:selected.cluster.projectId,clusterId:selected.cluster.id,offerId:selected.offerId,offerVersion:selected.offerVersion}});toast('Marketplace installation planning queued.');await loadMarketplace();}catch(error){toast(error.message,'error');}};
$('#marketplace-recommend').onclick=async()=>{const selected=marketplaceSelection(),objective=$('#marketplace-objective').value.trim();if(!selected.cluster||!objective){toast('Select a cluster and enter a concrete objective.','error');return;}try{await api('/api/v1/marketplace/recommendations',{method:'POST',headers:{'Idempotency-Key':idempotency('marketplace-recommend')},body:{projectId:selected.cluster.projectId,clusterId:selected.cluster.id,objective}});toast('Advisory recorded. No action was executed.');await loadMarketplace();}catch(error){toast(error.message,'error');}};
$('#marketplace-installation-grid').onclick=async event=>{const button=event.target.closest('[data-marketplace-action]');if(!button)return;const view=state.marketplaceInstallations.find(item=>(item.installation||item).id===button.dataset.id);if(!view)return;const installation=view.installation||view,action=button.dataset.marketplaceAction;if(action==='inspect'){showDetails('Marketplace installation',`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(installation.id)}</dd><dt>State</dt><dd>${badge(installation.state)}</dd><dt>Offer</dt><dd class="technical">${esc(`${installation.sourceId}@${installation.sourceVersion}`)}</dd><dt>Namespace</dt><dd class="technical">${esc(installation.targetNamespace)}</dd><dt>Desired digest</dt><dd class="technical">${esc(installation.desiredDigest)}</dd><dt>Observed digest</dt><dd class="technical">${esc(installation.observedDigest||'—')}</dd><dt>Destructive operation</dt><dd class="technical">${esc(installation.destructiveOperationId||'—')}</dd><dt>Error</dt><dd>${esc(installation.lastError||'—')}</dd></dl><div class="detail-section"><h3>Plan</h3>${renderPlanChanges(installation.plan)}</div>`);return;}const headers={'If-Match':`"${installation.revision}"`};if(action==='approve'&&!await confirmAction('Approve marketplace installation',`Approve the exact plan for ${installation.sourceId}@${installation.sourceVersion}?`))return;let payload={};if(action==='uninstall'){if(!await confirmAction('Uninstall marketplace offer',`Remove only managed resources for ${installation.sourceId}? The namespace is preserved.`,true))return;const checkpointId=await chooseDestructiveRecoveryCheckpoint('Bind recovery before marketplace uninstall',installation.projectId,installation.clusterId);if(!checkpointId)return;headers['X-Confirm-Uninstall']='remove-marketplace-installation';payload={recoveryCheckpointId:checkpointId};}try{await api(`/api/v1/marketplace/installations/${installation.id}/${action}`,{method:'POST',headers,body:payload});toast(`Marketplace ${action} accepted.`);await loadMarketplace();}catch(error){toast(error.message,'error');}};

async function loadBaselines(){
  try{
    const [baselines,clusterRows,deployments,recoveryCheckpoints]=await Promise.all([softApi('/api/v1/baselines',[],'baselines'),softApi('/api/v1/clusters',[],'clusters'),softApi('/api/v1/baseline-deployments',[],'baseline deployments'),softApi('/api/v1/recovery-checkpoints',[],'recovery checkpoints')]);
    Object.assign(state,{baselines,clusters:clusterRows,baselineDeployments:deployments,recoveryCheckpoints});
    const clusters=clusterRows.map(row=>row.cluster||row);
    setOptions($('#baseline-cluster'),clusters,item=>item.id,item=>`${item.displayName} · ${item.kubernetesVersion||'version pending'}`,'Connect a cluster first');
    setOptions($('#baseline-definition'),baselines,item=>`${item.id}@${item.version}`,item=>`${item.displayName} · ${item.version}`,'No admitted baselines');
    prerequisite($('#baselines-prerequisite'),clusters.length>0,'A connected cluster with fresh inventory is required before live planning.','clusters','Connect a cluster');
    setIntrinsicDisabled($('#baseline-form').querySelector('button[type="submit"]'), !clusters.length||!baselines.length);
    $('#baseline-deployment-grid').innerHTML=deployments.length?latest(deployments).map(d=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(d.baselineId)} ${esc(d.baselineVersion||'')}</h3><div class="resource-meta">${badge(d.state)}${badge(d.risk)}${d.planImpact?.digest?badge(d.planImpact.approvalReady?'IMPACT READY':'IMPACT BLOCKED'):badge('IMPACT PENDING')}</div></div></div><p>${technical(d.targetNamespace)} · ${technical(d.clusterId)}</p><div class="resource-details">${detailRow('Desired',shortDigest(d.desiredDigest))}${detailRow('Observed',shortDigest(d.observedDigest))}${detailRow('Plan inventory',shortDigest(d.planInventoryDigest))}${detailRow('Plan impact',shortDigest(d.planImpactDigest))}${detailRow('Completion evidence',d.evidenceDigest?`${(d.evidence||[]).length} sealed · ${shortDigest(d.evidenceDigest)}`:'Pending')}${detailRow('Disruption',d.planImpact?.disruption?.level||'UNKNOWN')}${detailRow('Maintenance',d.planImpact?.disruption?.maintenanceRecommendation||'UNKNOWN')}${detailRow('Capacity',d.planImpact?.capacity?.demandDeltaKnown?`${d.planImpact.capacity.cpuRequestDeltaMilli||0}m · ${bytes(d.planImpact.capacity.memoryRequestDeltaBytes||0)} · ${d.planImpact.capacity.podReplicaDelta||0} pods`:'UNKNOWN')}${detailRow('Plan valid until',formatDate(d.planExpiresAt))}${detailRow('Revalidations',d.planRevalidationCount||0)}${detailRow('Pending action',d.pendingAction||'—')}${detailRow('Revision',d.revision)}</div>${d.lastError?`<div class="warning-banner">${esc(d.lastError)}</div>`:''}${d.state==='AWAITING_APPROVAL'&&!planApprovalReady(d)?`<div class="warning-banner"><strong>Approval unavailable.</strong><br>Impact, rollback, or evidence collection planning is missing or has blockers. Revalidate after fixing API/CRD/capacity/recovery prerequisites.</div>`:''}<details><summary>Planned changes (${(d.plan||[]).length})</summary>${renderPlanChanges(d.plan)}</details><details><summary>Impact, capacity & maintenance</summary>${renderPlanImpact(d.planImpact)}</details><div class="resource-actions">${d.state==='AWAITING_APPROVAL'&&planApprovalReady(d)?approvalControl(d,'Approve apply',`data-baseline-action="approve" data-id="${esc(d.id)}"`):''}${['AWAITING_APPROVAL','QUEUED'].includes(d.state)?`<button type="button" class="secondary small-button" data-baseline-action="revalidate" data-id="${esc(d.id)}">Revalidate plan</button>`:''}${d.state==='FAILED'&&d.pendingAction!=='ROLLBACK'?`<button type="button" class="primary small-button" data-baseline-action="retry" data-id="${esc(d.id)}">Retry ${esc((d.pendingAction||'operation').toLowerCase())}</button>`:''}${['SUCCEEDED','FAILED','ROLLBACK_QUEUED'].includes(d.state)?`<button type="button" class="danger small-button" data-baseline-action="rollback" data-id="${esc(d.id)}">${d.state==='ROLLBACK_QUEUED'?'Refresh recovery':'Roll back'}</button>`:''}<button type="button" class="secondary small-button" data-baseline-action="inspect" data-id="${esc(d.id)}">Inspect</button></div></article>`).join(''):emptyState('No baseline deployments','Connect a cluster and create the first live plan.');
  }catch(error){$('#baseline-deployment-grid').innerHTML=errorState(error.message);}
}
$('#baseline-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const cluster=state.clusters.map(row=>row.cluster||row).find(item=>item.id===$('#baseline-cluster').value);const [baselineId,baselineVersion]=($('#baseline-definition').value||'').split('@');try{await api('/api/v1/baseline-deployments',{method:'POST',headers:{'Idempotency-Key':idempotency('baseline')},body:{projectId:cluster.projectId,clusterId:cluster.id,baselineId,baselineVersion}});toast('Live baseline planning queued.');await loadBaselines();}catch(error){toast(error.message,'error');}};
$('#baseline-deployment-grid').onclick=async event=>{const button=event.target.closest('[data-baseline-action]');if(!button)return;const deployment=state.baselineDeployments.find(item=>item.id===button.dataset.id);if(!deployment)return;const action=button.dataset.baselineAction;if(action==='inspect'){showDetails(`${deployment.baselineId} ${deployment.baselineVersion||''}`,`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(deployment.id)}</dd><dt>State</dt><dd>${badge(deployment.state)}</dd><dt>Cluster</dt><dd class="technical">${esc(deployment.clusterId)}</dd><dt>Namespace</dt><dd class="technical">${esc(deployment.targetNamespace)}</dd><dt>Desired digest</dt><dd class="technical">${esc(deployment.desiredDigest)}</dd><dt>Observed digest</dt><dd class="technical">${esc(deployment.observedDigest||'—')}</dd><dt>Plan context</dt><dd class="technical">${esc(deployment.planContextDigest||'—')}</dd><dt>Plan inventory</dt><dd class="technical">${esc(deployment.planInventoryDigest||'—')}</dd><dt>Plan valid until</dt><dd>${formatDate(deployment.planExpiresAt)}</dd><dt>Revalidations</dt><dd>${esc(deployment.planRevalidationCount||0)}</dd><dt>Requested by</dt><dd>${esc(deployment.requestedBy||'—')}</dd><dt>Approved by</dt><dd>${esc(deployment.approvedBy||'—')}</dd><dt>Destructive operation</dt><dd class="technical">${esc(deployment.destructiveOperationId||'—')}</dd><dt>Evidence digest</dt><dd class="technical">${esc(deployment.evidenceDigest||'—')}</dd><dt>Error</dt><dd>${esc(deployment.lastError||'—')}</dd></dl><div class="detail-section"><h3>Plan</h3>${renderPlanChanges(deployment.plan)}</div><div class="detail-section"><h3>Impact, capacity & maintenance</h3>${renderPlanImpact(deployment.planImpact)}</div><div class="detail-section"><h3>Collected completion evidence</h3>${renderCollectedBaselineEvidence(deployment)}</div>`);return;}if(action==='approve'&&!await confirmAction('Approve baseline apply',`Approve the exact ${deployment.plan?.length||0}-change plan for ${deployment.baselineId}@${deployment.baselineVersion}?`))return;let payload={};if(action==='rollback'){if(!await confirmAction('Roll back baseline',`Queue rollback for ${deployment.baselineId}@${deployment.baselineVersion}? Only product-managed resources are affected.`,true))return;const checkpointId=await chooseDestructiveRecoveryCheckpoint('Bind recovery before baseline rollback',deployment.projectId,deployment.clusterId);if(!checkpointId)return;payload={recoveryCheckpointId:checkpointId};}try{await api(`/api/v1/baseline-deployments/${deployment.id}/${action}`,{method:'POST',headers:{'If-Match':`"${deployment.revision}"`},body:payload});toast(`Baseline ${action} accepted.`);await loadBaselines();}catch(error){toast(error.message,'error');}};

async function loadVerification(){
  try{
    const [deployments,verifications,closures,certifications,projects,clusterRows,catalogReleases]=await Promise.all([softApi('/api/v1/baseline-deployments',[],'baseline deployments'),softApi('/api/v1/runtime-verifications',[],'runtime verifications'),softApi('/api/v1/runtime-closure-campaigns',[],'closure campaigns'),softApi('/api/v1/runtime-certifications',[],'runtime certifications'),softApi('/api/v1/projects',[],'projects'),softApi('/api/v1/clusters',[],'clusters'),softApi('/api/v1/catalog-releases',[],'catalog releases')]);
    Object.assign(state,{baselineDeployments:deployments,verifications,closures,runtimeCertifications:certifications,projects,clusters:clusterRows,catalogReleases});
    const successful=deployments.filter(d=>d.state==='SUCCEEDED'&&d.desiredDigest===d.observedDigest);
    setOptions($('#verification-baseline'),successful,item=>item.id,item=>`${item.baselineId}@${item.baselineVersion||''} · ${item.clusterId}`,'No successful baseline deployment');
    const closureCandidates=deployments.filter(d=>!['ROLLBACK_QUEUED','ROLLING_BACK','ROLLED_BACK'].includes(d.state));
    setOptions($('#closure-baseline'),closureCandidates,item=>item.id,item=>`${item.baselineId}@${item.baselineVersion||''} · ${item.state}`,'No eligible baseline deployment');
    prerequisite($('#verification-prerequisite'),deployments.length>0,'A baseline deployment is required before verification or closure. Certification additionally requires a fresh connected cluster and a published RENDER-or-higher Catalog release.','clusters','Connect a cluster');
    setIntrinsicDisabled($('#verification-form').querySelector('button[type="submit"]'), !successful.length);
    setIntrinsicDisabled($('#closure-form').querySelector('button[type="submit"]'), !closureCandidates.length);

    setOptions($('#runtime-certification-project'),projects,item=>item.id,item=>`${item.displayName} · ${item.name}`,'Create a project first');
    const certificationProject=$('#runtime-certification-project').value;
    const clusters=clusterRows.map(row=>row.cluster||row).filter(cluster=>cluster.projectId===certificationProject&&cluster.inventoryDigest);
    setOptions($('#runtime-certification-cluster'),clusters,item=>item.id,item=>`${item.displayName} · ${item.kubernetesVersion||'version pending'} · ${shortDigest(item.inventoryDigest)}`,'Fresh cluster inventory required');
    const renderable=catalogReleases.filter(release=>release.state==='PUBLISHED'&&['RENDER','RUNTIME','PRODUCTION'].includes(release.channel));
    setOptions($('#runtime-certification-catalog'),renderable,item=>item.id,item=>`${item.catalogName}@${item.catalogVersion} · ${item.channel} · ${shortDigest(item.manifestDigest)}`,'Publish a RENDER-or-higher Catalog release first');
    setIntrinsicDisabled($('#runtime-certification-form').querySelector('button[type="submit"]'), !projects.length||!clusters.length||!renderable.length);

    $('#runtime-certification-grid').innerHTML=certifications.length?latest(certifications).map(run=>{
      const passed=(run.checks||[]).filter(check=>check.status==='PASS').length;
      const blocked=(run.checks||[]).filter(check=>check.status==='BLOCKED').length;
      return `<article class="resource-card"><div class="resource-header"><div><h3>${esc(run.profile)}</h3><div class="resource-meta">${badge(run.state)}${badge(run.phase)}${badge(`${passed}/${(run.checks||[]).length} PASS`)}${blocked?badge(`${blocked} BLOCKED`):''}</div></div></div><p>${technical(run.namespace)} · ${technical(run.clusterId)}</p><div class="resource-details">${detailRow('Catalog',run.catalogReleaseId,true)}${detailRow('Inventory',shortDigest(run.inventoryDigest))}${detailRow('Source lock',shortDigest(run.sourceLockDigest))}${detailRow('Rendered',shortDigest(run.renderedDigest))}${detailRow('Resources',run.resourceCount||0)}${detailRow('Install checkpoint',shortDigest(run.installCheckpointDigest))}${detailRow('Evidence',shortDigest(run.evidenceDigest))}${detailRow('Expires',formatDate(run.expiresAt))}${detailRow('Attempt',run.taskAttempt||0)}</div>${run.lastError?`<div class="warning-banner">${esc(run.lastError)}</div>`:''}<details><summary>Certification checks (${(run.checks||[]).length})</summary><div class="activity-list">${(run.checks||[]).map(check=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">${check.status==='PASS'?'✓':check.status==='BLOCKED'?'⏸':'!'}</span><div><strong>${esc(check.key)}</strong><small>${esc(check.detail||'No detail')}</small></div></div>${badge(check.status)}</div>`).join('')||'<p>No checks reported yet.</p>'}</div></details><div class="resource-actions">${run.state==='SUCCEEDED'?`<a class="secondary small-button" href="/api/v1/runtime-certifications/${esc(run.id)}/report">View report</a><button type="button" class="danger small-button" data-certification-action="revoke" data-id="${esc(run.id)}">Revoke evidence</button>`:''}<button type="button" class="secondary small-button" data-certification-action="inspect" data-id="${esc(run.id)}">Inspect</button></div></article>`;
    }).join(''):emptyState('No runtime certification runs','Select a fresh connected cluster and a published RENDER-or-higher Catalog release.');

    $('#runtime-verification-grid').innerHTML=verifications.length?latest(verifications).map(v=>{
      const passed=(v.checks||[]).filter(c=>c.status==='PASS').length;
      return `<article class="resource-card"><div class="resource-header"><div><h3>${esc(v.state)}</h3><div class="resource-meta">${badge(v.state)}${badge(`${passed}/${(v.checks||[]).length} PASS`)}</div></div></div><p>Baseline ${technical(v.baselineDeploymentId)}</p><div class="resource-details">${detailRow('Probe image',v.probeImage||'—',true)}${detailRow('Desired',shortDigest(v.desiredDigest))}${detailRow('Observed',shortDigest(v.observedDigest))}${detailRow('Report',shortDigest(v.reportDigest))}</div>${v.lastError?`<div class="warning-banner">${esc(v.lastError)}</div>`:''}<details><summary>Runtime checks (${(v.checks||[]).length})</summary><div class="activity-list">${(v.checks||[]).map(check=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">${check.status==='PASS'?'✓':'!'}</span><div><strong>${esc(check.key)}</strong><small>${esc(check.detail||'No detail')}</small></div></div>${badge(check.status)}</div>`).join('')||'<p>No checks reported yet.</p>'}</div></details><div class="resource-actions">${v.state==='FAILED'?`<button type="button" class="primary small-button" data-verification-action="retry" data-id="${esc(v.id)}">Retry verification</button>`:''}${v.state==='SUCCEEDED'?`<a class="secondary small-button" href="/api/v1/runtime-verifications/${esc(v.id)}/report">Download report</a>`:''}<button type="button" class="secondary small-button" data-verification-action="inspect" data-id="${esc(v.id)}">Inspect</button></div></article>`;
    }).join(''):emptyState('No runtime verification','Apply a baseline successfully, then run the digest-pinned probe.');
    $('#runtime-closure-grid').innerHTML=closures.length?latest(closures).map(c=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(c.state)}</h3><div class="resource-meta">${badge(c.state)}${c.nextAction?badge(c.nextAction):''}</div></div></div><p>${esc(c.summary||'Awaiting controller action')}</p><div class="resource-details">${detailRow('Baseline',c.baselineDeploymentId,true)}${detailRow('Verification',c.runtimeVerificationId||'—',true)}${detailRow('Desired',shortDigest(c.desiredDigest))}${detailRow('Observed',shortDigest(c.observedDigest))}${detailRow('Evidence',shortDigest(c.evidenceDigest))}</div>${c.lastError?`<div class="warning-banner">${esc(c.lastError)}</div>`:''}<div class="resource-actions">${c.state!=='SUCCEEDED'&&c.state!=='FAILED'?`<button type="button" class="primary small-button" data-closure-action="advance" data-id="${esc(c.id)}">Advance one step</button>`:''}${c.state==='FAILED'?`<button type="button" class="primary small-button" data-closure-action="retry" data-id="${esc(c.id)}">Retry failed step</button>`:''}${c.state==='SUCCEEDED'?`<button type="button" class="primary small-button" data-closure-action="verify" data-viewer-safe="true" data-id="${esc(c.id)}">Verify evidence</button><a class="secondary small-button" href="/api/v1/runtime-closure-campaigns/${esc(c.id)}/report">Download closure report</a>`:''}<button type="button" class="secondary small-button" data-closure-action="inspect" data-id="${esc(c.id)}">Inspect</button></div></article>`).join(''):emptyState('No closure campaigns','Select a baseline deployment and create the first resumable campaign.');
  }catch(error){$('#runtime-verification-grid').innerHTML=errorState(error.message);$('#runtime-closure-grid').innerHTML=errorState(error.message);$('#runtime-certification-grid').innerHTML=errorState(error.message);}
}
$('#runtime-certification-project').onchange=()=>loadVerification();
$('#runtime-certification-profile').onchange=()=>{const profile=$('#runtime-certification-profile').value;$('#runtime-certification-namespace').value=profile==='TARGET_RUNTIME_V1'?'4so-cert-target-runtime':profile==='OBSERVABILITY_V1'?'4so-cert-observability':'4so-cert-foundation';};
$('#runtime-certification-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const body={projectId:$('#runtime-certification-project').value,clusterId:$('#runtime-certification-cluster').value,catalogReleaseId:$('#runtime-certification-catalog').value,profile:$('#runtime-certification-profile').value,namespace:$('#runtime-certification-namespace').value.trim()};try{const result=await api('/api/v1/runtime-certifications',{method:'POST',headers:{'Idempotency-Key':idempotency('runtime-certification')},body});toast(result.run?.state==='BLOCKED'?'Certification created as BLOCKED; inspect missing real capabilities.':'Runtime certification queued for the connected agent.',result.run?.state==='BLOCKED'?'warning':'success');await loadVerification();}catch(error){toast(error.message,'error');}};
$('#runtime-certification-grid').onclick=async event=>{const button=event.target.closest('[data-certification-action]');if(!button)return;const run=state.runtimeCertifications.find(item=>item.id===button.dataset.id);if(!run)return;const action=button.dataset.certificationAction;if(action==='inspect'){showDetails('Runtime certification',`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(run.id)}</dd><dt>Profile</dt><dd>${badge(run.profile)}</dd><dt>State</dt><dd>${badge(run.state)}</dd><dt>Phase</dt><dd>${badge(run.phase)}</dd><dt>Project</dt><dd class="technical">${esc(run.projectId)}</dd><dt>Cluster</dt><dd class="technical">${esc(run.clusterId)}</dd><dt>Catalog release</dt><dd class="technical">${esc(run.catalogReleaseId)}</dd><dt>Namespace</dt><dd class="technical">${esc(run.namespace)}</dd><dt>Inventory digest</dt><dd class="technical">${esc(run.inventoryDigest||'—')}</dd><dt>Environment fingerprint</dt><dd class="technical">${esc(run.environmentFingerprint||'—')}</dd><dt>Manifest digest</dt><dd class="technical">${esc(run.manifestDigest||'—')}</dd><dt>Source-lock digest</dt><dd class="technical">${esc(run.sourceLockDigest||'—')}</dd><dt>Rendered digest</dt><dd class="technical">${esc(run.renderedDigest||'—')}</dd><dt>Checkpoint</dt><dd class="technical">${esc(run.installCheckpointDigest||'—')}</dd><dt>Evidence</dt><dd class="technical">${esc(run.evidenceDigest||'—')}</dd><dt>Expires</dt><dd>${esc(formatDate(run.expiresAt))}</dd><dt>Error / blocker</dt><dd>${esc(run.lastError||'—')}</dd></dl><div class="warning-banner">External Live Certified: false · Production Ready: false. This record proves only the selected profile on the bound inventory/context.</div>`);return;}if(action==='revoke'){if(!await confirmAction('Revoke certification evidence',`Revoke ${run.profile} evidence for ${run.namespace}?`,true))return;try{await api(`/api/v1/runtime-certifications/${run.id}/revoke`,{method:'POST',headers:{'If-Match':`"${run.revision}"`},body:{}});toast('Certification evidence revoked.');await loadVerification();}catch(error){toast(error.message,'error');}}};
$('#verification-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const deployment=state.baselineDeployments.find(item=>item.id===$('#verification-baseline').value);try{await api('/api/v1/runtime-verifications',{method:'POST',headers:{'Idempotency-Key':idempotency('runtime-verification')},body:{projectId:deployment.projectId,clusterId:deployment.clusterId,baselineDeploymentId:deployment.id}});toast('Runtime verification queued for the connected agent.');await loadVerification();}catch(error){toast(error.message,'error');}};
$('#closure-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const deployment=state.baselineDeployments.find(item=>item.id===$('#closure-baseline').value);try{await api('/api/v1/runtime-closure-campaigns',{method:'POST',headers:{'Idempotency-Key':idempotency('runtime-closure')},body:{projectId:deployment.projectId,clusterId:deployment.clusterId,baselineDeploymentId:deployment.id}});toast('Runtime closure campaign created.');await loadVerification();}catch(error){toast(error.message,'error');}};
$('#runtime-verification-grid').onclick=async event=>{const button=event.target.closest('[data-verification-action]');if(!button)return;const record=state.verifications.find(item=>item.id===button.dataset.id);if(!record)return;if(button.dataset.verificationAction==='inspect'){showDetails('Runtime verification',`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(record.id)}</dd><dt>State</dt><dd>${badge(record.state)}</dd><dt>Baseline</dt><dd class="technical">${esc(record.baselineDeploymentId)}</dd><dt>Probe image</dt><dd class="technical">${esc(record.probeImage||'—')}</dd><dt>Desired digest</dt><dd class="technical">${esc(record.desiredDigest||'—')}</dd><dt>Observed digest</dt><dd class="technical">${esc(record.observedDigest||'—')}</dd><dt>Report digest</dt><dd class="technical">${esc(record.reportDigest||'—')}</dd><dt>Error</dt><dd>${esc(record.lastError||'—')}</dd></dl>`);return;}try{await api(`/api/v1/runtime-verifications/${record.id}/retry`,{method:'POST',headers:{'If-Match':`"${record.revision}"`},body:{}});toast('Runtime verification re-queued with the same identity and desired digest.');await loadVerification();}catch(error){toast(error.message,'error');}};
$('#runtime-closure-grid').onclick=async event=>{const button=event.target.closest('[data-closure-action]');if(!button)return;const record=state.closures.find(item=>item.id===button.dataset.id);if(!record)return;const action=button.dataset.closureAction;if(action==='inspect'){showDetails('Runtime closure campaign',`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(record.id)}</dd><dt>State</dt><dd>${badge(record.state)}</dd><dt>Next action</dt><dd>${esc(record.nextAction||'—')}</dd><dt>Summary</dt><dd>${esc(record.summary||'—')}</dd><dt>Baseline</dt><dd class="technical">${esc(record.baselineDeploymentId)}</dd><dt>Verification</dt><dd class="technical">${esc(record.runtimeVerificationId||'—')}</dd><dt>Evidence digest</dt><dd class="technical">${esc(record.evidenceDigest||'—')}</dd><dt>Error</dt><dd>${esc(record.lastError||'—')}</dd></dl>`);return;}try{if(action==='verify'){const report=await api(`/api/v1/runtime-closure-campaigns/${record.id}/report`);const result=await api('/api/v1/runtime-closure-reports/verify',{method:'POST',body:report});showDetails(t('verification.verifiedTitle','Verified closure evidence'),`<div class="success-banner">${esc(t('verification.verifiedMessage','Independent digest verification passed.'))}</div><dl class="key-value"><dt>Campaign</dt><dd class="technical">${esc(result.campaignId)}</dd><dt>Project</dt><dd class="technical">${esc(result.projectId)}</dd><dt>Cluster</dt><dd class="technical">${esc(result.clusterId)}</dd><dt>Baseline</dt><dd class="technical">${esc(result.baselineDeploymentId)}</dd><dt>Verification</dt><dd class="technical">${esc(result.runtimeVerificationId)}</dd><dt>Evidence digest</dt><dd class="technical">${esc(result.evidenceDigest)}</dd><dt>Canonicalization</dt><dd class="technical">${esc(result.canonicalization)}</dd></dl><div class="warning-banner">${esc(t('verification.integrityOnly','This verifies evidence integrity only; Runtime Certified, HA Certified and Production Ready remain false.'))}</div>`);return;}await api(`/api/v1/runtime-closure-campaigns/${record.id}/${action}`,{method:'POST',headers:{'If-Match':`"${record.revision}"`},body:{}});toast(`Closure campaign ${action} accepted.`);await loadVerification();}catch(error){toast(error.message,'error');}};

async function loadFleet(){
  try{
    const [projects,clusters,groups,drifts,campaigns,baselines,recoveryCheckpoints]=await Promise.all([softApi('/api/v1/projects',[],'projects'),softApi('/api/v1/clusters',[],'clusters'),softApi('/api/v1/fleet-groups',[],'fleet groups'),softApi('/api/v1/drift-scans',[],'drift scans'),softApi('/api/v1/upgrade-campaigns',[],'upgrade campaigns'),softApi('/api/v1/baselines',[],'baselines'),softApi('/api/v1/recovery-checkpoints',[],'recovery checkpoints')]);
    Object.assign(state,{projects,clusters,fleetGroups:groups,driftScans:drifts,upgradeCampaigns:campaigns,baselines,recoveryCheckpoints});
    setOptions($('#fleet-project'),projects,item=>item.id,item=>`${item.displayName} · ${item.name}`,'Create a project first');
    const projectId=$('#fleet-project').value;
    const fleetHealth=projectId?await api(`/api/v1/fleet/health?projectId=${encodeURIComponent(projectId)}`):{summary:{total:0,healthy:0,warning:0,stale:0,critical:0,online:0,eol:0},clusters:[]}; state.fleetHealth=fleetHealth;
    const projectClusters=clusters.map(row=>row.cluster||row).filter(cluster=>!projectId||cluster.projectId===projectId);
    setOptions($('#fleet-clusters'),projectClusters,item=>item.id,item=>`${item.displayName} · ${item.kubernetesVersion||'version pending'}`,'Connect clusters first');
    setOptions($('#recovery-cluster'),projectClusters.filter(item=>item.inventoryDigest),item=>item.id,item=>`${item.displayName} · ${shortDigest(item.inventoryDigest)}`,'Fresh cluster inventory required');
    if(!$('#recovery-completed-at').value) $('#recovery-completed-at').value=localDateTimeValue(new Date(Date.now()-5*60000));
    if(!$('#recovery-expires-at').value) $('#recovery-expires-at').value=localDateTimeValue(new Date(Date.now()+24*3600000));
    const visibleCheckpoints=recoveryCheckpoints.filter(item=>!projectId||item.projectId===projectId);
    $('#recovery-checkpoint-grid').innerHTML=visibleCheckpoints.length?latest(visibleCheckpoints).map(item=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.provider)} · ${esc(item.reference)}</h3><div class="resource-meta">${badge(item.state)}${new Date(item.expiresAt)>new Date()?badge('VALID'):badge('EXPIRED')}</div></div></div><div class="resource-details">${detailRow('Cluster',item.clusterId,true)}${detailRow('Evidence',shortDigest(item.evidenceDigest))}${detailRow('Inventory',shortDigest(item.inventoryDigest))}${detailRow('Completed',formatDate(item.completedAt))}${detailRow('Expires',formatDate(item.expiresAt))}${detailRow('Revision',item.revision)}</div><div class="resource-actions">${item.state==='VERIFIED'?`<button type="button" class="danger small-button" data-recovery-action="revoke" data-id="${esc(item.id)}">Revoke checkpoint</button>`:''}<button type="button" class="secondary small-button" data-recovery-action="inspect" data-id="${esc(item.id)}">Inspect</button></div></article>`).join(''):emptyState('No recovery checkpoints','Register backup evidence captured against current cluster inventory before creating an upgrade campaign.');
    const visibleGroups=groups.filter(group=>!projectId||group.projectId===projectId);
    prerequisite($('#fleet-prerequisite'),projectClusters.length>0,'At least one connected cluster is required before creating a fleet.','clusters','Connect clusters');
    setIntrinsicDisabled($('#fleet-group-form').querySelector('button[type="submit"]'), !projectClusters.length);
    const hs=fleetHealth.summary||{};
    $('#fleet-health-summary').innerHTML=[['Clusters',hs.total||0,`${hs.online||0} online`],['Healthy',hs.healthy||0,'fresh and supported'],['Warning',hs.warning||0,`${hs.eol||0} EOL`],['Stale / critical',(hs.stale||0)+(hs.critical||0),'requires operator attention']].map(([label,value,detail])=>`<article class="metric-card"><strong>${esc(value)}</strong><span>${esc(label)}</span><small>${esc(detail)}</small></article>`).join('');
    $('#fleet-health-grid').innerHTML=(fleetHealth.clusters||[]).length?(fleetHealth.clusters||[]).map(row=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(row.displayName||row.name)}</h3><div class="resource-meta">${badge(row.health)}${badge(row.online?'ONLINE':'OFFLINE')}${badge(row.kubernetesSupport?.status||'UNKNOWN')}</div></div></div><div class="resource-details">${detailRow('Kubernetes',row.kubernetesVersion||'—',true)}${detailRow('Support EOL',row.kubernetesSupport?.endOfLife?new Date(row.kubernetesSupport.endOfLife).toLocaleDateString():'unknown')}${detailRow('Nodes',`${row.readyNodes||0}/${row.nodeCount||0} Ready`)}${detailRow('Storage classes',row.storageClassCount||0)}${detailRow('Default storage',row.defaultStorageClass||'—',true)}${detailRow('CPU allocatable',`${row.capacity?.cpuAllocatableMilli||0}m`)}${detailRow('Memory allocatable',bytes(row.capacity?.memoryAllocatableBytes))}${detailRow('CNI',row.networking?.cni||'unknown',true)}${detailRow('Ingress',(row.networking?.ingressControllers||[]).join(', ')||'unknown',true)}</div>${(row.warnings||[]).length?`<div class="warning-banner">${(row.warnings||[]).map(esc).join('<br>')}</div>`:''}<div class="resource-actions"><button type="button" class="secondary small-button" data-health-action="timeline" data-id="${esc(row.clusterId)}">Timeline</button><button type="button" class="secondary small-button" data-health-action="bundle" data-id="${esc(row.clusterId)}">Support bundle</button></div></article>`).join(''):emptyState('No fleet health data','Connect a cluster and wait for the first inventory report.');
    $('#fleet-group-grid').innerHTML=visibleGroups.length?visibleGroups.map(group=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(group.displayName)}</h3><div class="resource-meta">${badge(`${group.clusterIds.length} clusters`)}</div></div></div><div class="resource-details">${detailRow('Machine name',group.name,true)}${detailRow('Project',group.projectId,true)}${detailRow('Revision',group.revision)}</div><details><summary>Cluster IDs</summary><pre class="code-block technical" dir="ltr">${esc(group.clusterIds.join('\n'))}</pre></details><div class="resource-actions"><button type="button" class="secondary small-button" data-fleet-action="drift" data-id="${esc(group.id)}">Run drift scan</button><button type="button" class="primary small-button" data-fleet-action="upgrade" data-id="${esc(group.id)}">Create upgrade campaign</button></div></article>`).join(''):emptyState('No fleet groups','Select connected clusters and create the first fleet group.');
    $('#drift-scan-grid').innerHTML=drifts.length?latest(drifts).map(scan=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(scan.state)}</h3><div class="resource-meta">${badge(scan.state)}${badge(`${(scan.targets||[]).length} targets`)}</div></div></div><p>${esc(scan.summary||'Agent checks are pending.')}</p><div class="activity-list">${(scan.targets||[]).map(target=>{const git=target.git;return `<div class="activity-item"><div class="activity-main"><span class="check-icon">${target.state==='IN_SYNC'?'✓':target.state==='FAILED'?'!':'○'}</span><div><strong class="technical">${esc(target.clusterId)}</strong><small>${esc(target.baselineVersion||'No baseline')} · ${(target.changes||[]).filter(change=>change.action!=='NOOP').length} baseline changes${git?` · Git ${esc(git.classification)}`:''}</small>${git?`<small>Base ${esc(shortDigest(git.baseDigest))} → Git ${esc(shortDigest(git.currentDigest))} → Live ${esc(shortDigest(git.observedDigest||'UNKNOWN'))}</small>${git.changedFiles?.length?`<small>${git.changedFiles.length} externally changed Git file(s)</small>`:''}`:''}${target.comparison?`<small>Product ${esc(shortDigest(target.comparison.productGeneratedDigest))}${target.comparison.gitDesiredDigest?` → Git ${esc(shortDigest(target.comparison.gitDesiredDigest))}`:''} → Live ${esc(shortDigest(target.comparison.liveObservedDigest||'UNKNOWN'))} · ${esc(target.comparison.classification)}</small>`:''}</div></div><div>${badge(target.state)}${git?badge(git.currentTrusted?'TRUSTED':'UNTRUSTED'):''}</div>${(target.findings||[]).length?`<div class="resource-details">${target.findings.map(finding=>`<div class="detail-row"><span>${badge(finding.severity)} ${badge(finding.category)} <strong>${esc(finding.code)}</strong></span><small>${esc(finding.summary)} · Owner ${esc(finding.owner)} · Seen ${esc(finding.occurrences||1)}×</small>${finding.remediation?.mode==='OPERATION'&&finding.remediation?.eligible?`<button type="button" class="secondary small-button" data-drift-action="remediate-finding" data-scan-id="${esc(scan.id)}" data-cluster-id="${esc(target.clusterId)}" data-fingerprint="${esc(finding.fingerprint)}">Queue ${esc(finding.remediation.action)}</button>`:`<small>Remediation: ${esc(finding.remediation?.action||'REVIEW')} · ${esc(finding.remediation?.mode||'GUIDANCE')}</small>`}</div>`).join('')}</div>`:''}${git?.adoptable?`<button type="button" class="secondary small-button" data-drift-action="adopt-git" data-scan-id="${esc(scan.id)}" data-cluster-id="${esc(target.clusterId)}">Adopt trusted Git state</button>`:''}</div>`}).join('')}</div></article>`).join(''):emptyState('No drift scans','Run a live read-only drift scan from a fleet group.');
    $('#upgrade-campaign-grid').innerHTML=campaigns.length?latest(campaigns).map(campaign=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(campaign.targetVersion)}</h3><div class="resource-meta">${badge(campaign.state)}${badge(`wave ${campaign.currentWave||0}`)}</div></div></div><p>${esc(campaign.summary||'Awaiting campaign action.')}</p><div class="resource-details">${detailRow('Canary count',campaign.canaryCount)}${detailRow('Window start',formatDate(campaign.maintenanceWindowStart))}${detailRow('Window end',formatDate(campaign.maintenanceWindowEnd))}${detailRow('Plan valid until',formatDate(campaign.planExpiresAt))}${detailRow('Recovery checkpoints',(campaign.recoveryCheckpointIds||[]).length)}${detailRow('Revalidations',campaign.planRevalidationCount||0)}${detailRow('Revision',campaign.revision)}</div><details><summary>Targets (${(campaign.targets||[]).length})</summary><div class="activity-list">${(campaign.targets||[]).map(target=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">${target.wave}</span><div><strong class="technical">${esc(target.clusterId)}</strong><small>Wave ${target.wave}</small></div></div>${badge(target.state)}</div>`).join('')}</div></details><div class="resource-actions">${campaign.state==='AWAITING_APPROVAL'?approvalControl(campaign,'Approve campaign',`data-upgrade-action="approve" data-id="${esc(campaign.id)}"`):''}${['AWAITING_APPROVAL','QUEUED','RUNNING','PAUSED'].includes(campaign.state)?`<button type="button" class="secondary small-button" data-upgrade-action="revalidate" data-id="${esc(campaign.id)}">Revalidate / reschedule</button>`:''}${campaign.state==='RUNNING'?`<button type="button" class="secondary small-button" data-upgrade-action="pause" data-id="${esc(campaign.id)}">Pause safely</button>`:''}${campaign.state==='PAUSED'?`<button type="button" class="primary small-button" data-upgrade-action="resume" data-id="${esc(campaign.id)}">Resume campaign</button>`:''}${['QUEUED','RUNNING','HALTED','PAUSE_REQUESTED','CANCEL_REQUESTED'].includes(campaign.state)?`<button type="button" class="primary small-button" data-upgrade-action="advance" data-id="${esc(campaign.id)}">${['PAUSE_REQUESTED','CANCEL_REQUESTED'].includes(campaign.state)?'Drain active work':'Advance campaign'}</button>`:''}${!['SUCCEEDED','FAILED','CANCELLED','CANCEL_REQUESTED'].includes(campaign.state)?`<button type="button" class="danger small-button" data-upgrade-action="cancel" data-id="${esc(campaign.id)}">Cancel safely</button>`:''}<button type="button" class="secondary small-button" data-upgrade-action="inspect" data-id="${esc(campaign.id)}">Inspect</button></div></article>`).join(''):emptyState('No upgrade campaigns','Create an upgrade campaign from an eligible fleet group.');
  }catch(error){$('#fleet-health-grid').innerHTML=errorState(error.message);$('#recovery-checkpoint-grid').innerHTML=errorState(error.message);$('#fleet-group-grid').innerHTML=errorState(error.message);$('#drift-scan-grid').innerHTML=errorState(error.message);$('#upgrade-campaign-grid').innerHTML=errorState(error.message);}
}
async function downloadSupportBundle(body){ const result=await apiBlob('/api/v1/support-bundles',{method:'POST',body}); const match=/filename=\"?([^\";]+)\"?/i.exec(result.disposition); const name=match?.[1]||'4so-support-bundle.zip'; const url=URL.createObjectURL(result.blob); const a=document.createElement('a'); a.href=url; a.download=name; a.click(); setTimeout(()=>URL.revokeObjectURL(url),1500); $('#fleet-support-status').innerHTML=`<div class="success-banner">Bundle verified by the server before download · ${esc(result.redactions)} redactions · digest <span class="technical">${esc(result.digest||'—')}</span></div>`; }
$('#fleet-health-grid').onclick=async event=>{const button=event.target.closest('[data-health-action]');if(!button)return;try{if(button.dataset.healthAction==='timeline'){const events=await api(`/api/v1/clusters/${button.dataset.id}/timeline`);showDetails('Cluster timeline',events.length?`<div class="activity-list">${events.slice(0,100).map(item=>`<div class="activity-item"><div><strong>${esc(item.action)}</strong><small>${esc(item.resourceType)} · ${esc(item.resourceId)} · ${new Date(item.occurredAt).toLocaleString()}</small></div>${badge(item.actorId||'system')}</div>`).join('')}</div>`:emptyState('No timeline events','No related audit events are available yet.'));return;}await downloadSupportBundle({profile:'cluster-diagnostics',clusterId:button.dataset.id});toast('Cluster support bundle downloaded.');}catch(error){toast(error.message,'error');}};
$('#fleet-support-download').onclick=async()=>{const projectId=$('#fleet-project').value;if(!projectId){toast('Select a project first.','error');return;}try{await downloadSupportBundle({profile:'fleet-diagnostics',projectId});toast('Project support bundle downloaded.');}catch(error){toast(error.message,'error');}};
$('#recovery-checkpoint-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const cluster=state.clusters.map(row=>row.cluster||row).find(item=>item.id===$('#recovery-cluster').value);if(!cluster){toast('Select a cluster with current inventory.','error');return;}try{await api('/api/v1/recovery-checkpoints',{method:'POST',body:{projectId:cluster.projectId,clusterId:cluster.id,provider:$('#recovery-provider').value.trim(),reference:$('#recovery-reference').value.trim(),evidenceDigest:$('#recovery-evidence-digest').value.trim(),completedAt:new Date($('#recovery-completed-at').value).toISOString(),expiresAt:new Date($('#recovery-expires-at').value).toISOString()}});toast('Recovery checkpoint registered against current inventory.');$('#recovery-reference').value='';$('#recovery-evidence-digest').value='';await loadFleet();}catch(error){toast(error.message,'error');}};
$('#recovery-checkpoint-grid').onclick=async event=>{const button=event.target.closest('[data-recovery-action]');if(!button)return;const item=state.recoveryCheckpoints.find(row=>row.id===button.dataset.id);if(!item)return;if(button.dataset.recoveryAction==='inspect'){showDetails('Recovery checkpoint',`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(item.id)}</dd><dt>State</dt><dd>${badge(item.state)}</dd><dt>Cluster</dt><dd class="technical">${esc(item.clusterId)}</dd><dt>Provider</dt><dd>${esc(item.provider)}</dd><dt>Reference</dt><dd class="technical">${esc(item.reference)}</dd><dt>Evidence digest</dt><dd class="technical">${esc(item.evidenceDigest)}</dd><dt>Inventory digest</dt><dd class="technical">${esc(item.inventoryDigest)}</dd><dt>Completed</dt><dd>${formatDate(item.completedAt)}</dd><dt>Expires</dt><dd>${formatDate(item.expiresAt)}</dd></dl>`);return;}if(!await confirmAction('Revoke recovery checkpoint',`Revoke ${item.reference}? Campaigns that have not started must revalidate with new recovery evidence.`,true))return;try{await api(`/api/v1/recovery-checkpoints/${item.id}/revoke`,{method:'POST',headers:{'If-Match':`"${item.revision}"`},body:{}});toast('Recovery checkpoint revoked.');await loadFleet();}catch(error){toast(error.message,'error');}};
$('#fleet-project').onchange=loadFleet;
$('#fleet-group-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const clusterIds=$$('#fleet-clusters option:checked').map(option=>option.value);if(!clusterIds.length){toast('Select at least one connected cluster.','error');return;}try{await api('/api/v1/fleet-groups',{method:'POST',headers:{'Idempotency-Key':idempotency('fleet')},body:{projectId:$('#fleet-project').value,name:$('#fleet-name').value.trim(),displayName:$('#fleet-display-name').value.trim(),clusterIds}});toast('Fleet group created.');event.currentTarget.reset();await loadFleet();}catch(error){toast(error.message,'error');}};
$('#fleet-group-grid').onclick=async event=>{
  const button=event.target.closest('[data-fleet-action]'); if(!button)return;
  const group=state.fleetGroups.find(item=>item.id===button.dataset.id); if(!group)return;
  if(button.dataset.fleetAction==='drift'){try{const organization=$('#drift-git-organization').value.trim(),repository=$('#drift-git-repository').value.trim(),branch=$('#drift-git-branch').value.trim()||'main';if((organization&&!repository)||(!organization&&repository)){toast('Enter both Git organization and repository, or leave both empty.','error');return;}const body={projectId:group.projectId,fleetGroupId:group.id};if(organization&&repository)body.git={organization,repository,branch};await api('/api/v1/drift-scans',{method:'POST',headers:{'Idempotency-Key':idempotency('drift')},body});toast(organization?'Three-way Git + live drift scan queued.':'Live baseline drift scan queued.');await loadFleet();}catch(error){toast(error.message,'error');}return;}
  const targetOptions=state.baselines.filter(item=>item.id==='secure-namespace-foundation').map(item=>({value:item.version,label:`${item.displayName} · ${item.version}`}));
  const fields=[{name:'targetVersion',label:'Target baseline version',type:'select',options:targetOptions},{name:'maintenanceWindowStart',label:'Maintenance window start',type:'datetime-local',value:localDateTimeValue(new Date(Date.now()+5*60000))},{name:'maintenanceWindowEnd',label:'Maintenance window end',type:'datetime-local',value:localDateTimeValue(new Date(Date.now()+2*3600000))},{name:'canaryCount',label:'Canary clusters',type:'number',value:1,min:1,max:group.clusterIds.length},{name:'waveSize',label:'Wave size',type:'number',value:Math.min(2,group.clusterIds.length),min:1,max:group.clusterIds.length},{name:'haltAfterFailures',label:'Halt after failures',type:'number',value:1,min:1,max:group.clusterIds.length}];
  for(const clusterId of group.clusterIds){const cluster=(state.clusters.map(row=>row.cluster||row)).find(item=>item.id===clusterId);const eligible=state.recoveryCheckpoints.filter(item=>item.projectId===group.projectId&&item.clusterId===clusterId&&item.state==='VERIFIED'&&item.inventoryDigest===cluster?.inventoryDigest&&new Date(item.expiresAt)>new Date()).sort((a,b)=>new Date(b.completedAt)-new Date(a.completedAt));if(!eligible.length){toast(`Register a valid recovery checkpoint for ${cluster?.displayName||clusterId} first.`,'error');return;}fields.push({name:`checkpoint_${clusterId}`,label:`Recovery checkpoint · ${cluster?.displayName||clusterId}`,type:'select',options:eligible.map(item=>({value:item.id,label:`${item.provider} · ${item.reference} · expires ${formatDate(item.expiresAt)}`}))});}
  const values=await askFields('Create safe upgrade campaign',fields,'Create campaign'); if(!values)return;
  const recoveryCheckpointIds=group.clusterIds.map(id=>values[`checkpoint_${id}`]);
  try{await api('/api/v1/upgrade-campaigns',{method:'POST',headers:{'Idempotency-Key':idempotency('upgrade')},body:{projectId:group.projectId,fleetGroupId:group.id,baselineId:'secure-namespace-foundation',targetVersion:values.targetVersion,canaryCount:values.canaryCount,waveSize:values.waveSize,haltAfterFailures:values.haltAfterFailures,maintenanceWindowStart:new Date(values.maintenanceWindowStart).toISOString(),maintenanceWindowEnd:new Date(values.maintenanceWindowEnd).toISOString(),recoveryCheckpointIds}});toast('Upgrade campaign created with recovery and maintenance safety context.');await loadFleet();}catch(error){toast(error.message,'error');}
};
$('#drift-scan-grid').onclick=async event=>{const button=event.target.closest('[data-drift-action]');if(!button)return;if(button.dataset.driftAction==='adopt-git'){if(!await confirmAction('Adopt trusted external Git revision','This does not overwrite Git or live state. It only records the already-applied, platform-signed Git revision as the new drift base.'))return;try{await api(`/api/v1/drift-scans/${button.dataset.scanId}/adopt-git`,{method:'POST',body:{clusterId:button.dataset.clusterId}});toast('Trusted external Git revision adopted without overwrite. Run a new drift scan to confirm convergence.');await loadFleet();}catch(error){toast(error.message,'error');}return;}if(button.dataset.driftAction==='remediate-finding'){if(!await confirmAction('Queue drift remediation','This creates a durable, idempotent operation bound to this exact drift finding. It does not automatically overwrite Git.'))return;try{const result=await api(`/api/v1/drift-scans/${button.dataset.scanId}/targets/${button.dataset.clusterId}/findings/${button.dataset.fingerprint}/remediate`,{method:'POST',headers:{'Idempotency-Key':idempotency('drift-remediation')}});toast(`Remediation operation ${result.operation?.state||'QUEUED'}: ${result.operation?.id||''}`);await loadFleet();}catch(error){toast(error.message,'error');}}};
$('#upgrade-campaign-grid').onclick=async event=>{const button=event.target.closest('[data-upgrade-action]');if(!button)return;const campaign=state.upgradeCampaigns.find(item=>item.id===button.dataset.id);if(!campaign)return;const action=button.dataset.upgradeAction;if(action==='inspect'){showDetails('Upgrade campaign',`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(campaign.id)}</dd><dt>State</dt><dd>${badge(campaign.state)}</dd><dt>Baseline</dt><dd class="technical">${esc(campaign.baselineId)}@${esc(campaign.targetVersion)}</dd><dt>Current wave</dt><dd>${esc(campaign.currentWave||0)}</dd><dt>Maintenance window</dt><dd>${formatDate(campaign.maintenanceWindowStart)} → ${formatDate(campaign.maintenanceWindowEnd)}</dd><dt>Plan context</dt><dd class="technical">${esc(campaign.planContextDigest||'—')}</dd><dt>Plan expires</dt><dd>${formatDate(campaign.planExpiresAt)}</dd><dt>Recovery checkpoints</dt><dd class="technical">${esc((campaign.recoveryCheckpointIds||[]).join(', ')||'—')}</dd><dt>Pause count</dt><dd>${esc(campaign.pauseCount||0)}</dd><dt>Paused by / at</dt><dd>${esc(campaign.pausedBy||'—')} · ${formatDate(campaign.pausedAt)}</dd><dt>Cancel requested</dt><dd>${esc(campaign.cancelRequestedBy||'—')} · ${formatDate(campaign.cancelRequestedAt)}</dd><dt>Cancelled by / at</dt><dd>${esc(campaign.cancelledBy||'—')} · ${formatDate(campaign.cancelledAt)}</dd><dt>Control reason</dt><dd>${esc(campaign.controlReason||'—')}</dd><dt>Summary</dt><dd>${esc(campaign.summary||'—')}</dd><dt>Error</dt><dd>${esc(campaign.lastError||'—')}</dd></dl>`);return;}if(action==='approve'&&!await confirmAction('Approve upgrade campaign',`Approve rollout of ${campaign.baselineId}@${campaign.targetVersion} to ${(campaign.targets||[]).length} clusters?`))return;
if(action==='pause'){
  const values=await askFields('Pause upgrade campaign',[{name:'reason',label:'Reason',type:'text',value:'Operator pause between upgrade targets'}],'Request safe pause');if(!values)return;
  try{await api(`/api/v1/upgrade-campaigns/${campaign.id}/pause`,{method:'POST',headers:{'If-Match':`"${campaign.revision}"`},body:{reason:values.reason}});toast('Pause requested. Active work will drain to a safe point before the campaign pauses.');await loadFleet();}catch(error){toast(error.message,'error');}return;
}
if(action==='resume'){
  if(!await confirmAction('Resume upgrade campaign','Resume from the preserved wave and completed-target state? Maintenance, plan context, inventory and recovery evidence will be checked again.'))return;
  try{await api(`/api/v1/upgrade-campaigns/${campaign.id}/resume`,{method:'POST',headers:{'If-Match':`"${campaign.revision}"`},body:{}});toast('Upgrade campaign resumed from the preserved safe point.');await loadFleet();}catch(error){toast(error.message,'error');}return;
}
if(action==='cancel'){
  const values=await askFields('Cancel upgrade campaign',[{name:'reason',label:'Reason',type:'text',value:'Operator cancelled remaining rollout'}],'Continue to cancel');if(!values)return;
  if(!await confirmAction('Confirm bounded cancel','Completed targets remain upgraded. Active apply/verify/rollback work is allowed to drain safely; pending targets will never start.',true))return;
  try{await api(`/api/v1/upgrade-campaigns/${campaign.id}/cancel`,{method:'POST',headers:{'If-Match':`"${campaign.revision}"`},body:{reason:values.reason}});toast('Cancel accepted. Active work will drain before the campaign becomes CANCELLED.');await loadFleet();}catch(error){toast(error.message,'error');}return;
}
if(action==='revalidate'){
  const active=(campaign.targets||[]).some(target=>['PLANNING','APPLYING','VERIFYING','ROLLING_BACK'].includes(target.state));
  if(active){toast('Finish or halt the active target before revalidating between waves.','error');return;}
  const pending=(campaign.targets||[]).filter(target=>target.state==='PENDING');
  const fields=[{name:'maintenanceWindowStart',label:'Maintenance window start',type:'datetime-local',value:localDateTimeValue(new Date(Math.max(Date.now()+5*60000,new Date(campaign.maintenanceWindowStart||0).getTime()||0)))},{name:'maintenanceWindowEnd',label:'Maintenance window end',type:'datetime-local',value:localDateTimeValue(new Date(Math.max(Date.now()+2*3600000,new Date(campaign.maintenanceWindowEnd||0).getTime()||0)))}];
  const preserved=[];
  for(const target of (campaign.targets||[])){
    if(target.state!=='PENDING')continue;
    const cluster=state.clusters.map(row=>row.cluster||row).find(item=>item.id===target.clusterId);
    const eligible=state.recoveryCheckpoints.filter(item=>item.projectId===campaign.projectId&&item.clusterId===target.clusterId&&item.state==='VERIFIED'&&item.inventoryDigest===cluster?.inventoryDigest&&new Date(item.expiresAt)>new Date()).sort((a,b)=>new Date(b.completedAt)-new Date(a.completedAt));
    if(!eligible.length){toast(`Register a current recovery checkpoint for ${cluster?.displayName||target.clusterId} before revalidating.`,'error');return;}
    fields.push({name:`checkpoint_${target.clusterId}`,label:`Recovery checkpoint · ${cluster?.displayName||target.clusterId}`,type:'select',options:eligible.map(item=>({value:item.id,label:`${item.provider} · ${item.reference} · expires ${formatDate(item.expiresAt)}`}))});
  }
  for(const id of (campaign.recoveryCheckpointIds||[])){const cp=state.recoveryCheckpoints.find(item=>item.id===id);if(cp&&!pending.some(target=>target.clusterId===cp.clusterId))preserved.push(id);}
  const values=await askFields('Revalidate upgrade campaign',fields,'Revalidate');if(!values)return;
  const recoveryCheckpointIds=[...preserved,...pending.map(target=>values[`checkpoint_${target.clusterId}`])].filter(Boolean);
  try{await api(`/api/v1/upgrade-campaigns/${campaign.id}/revalidate`,{method:'POST',headers:{'If-Match':`"${campaign.revision}"`},body:{maintenanceWindowStart:new Date(values.maintenanceWindowStart).toISOString(),maintenanceWindowEnd:new Date(values.maintenanceWindowEnd).toISOString(),recoveryCheckpointIds}});toast('Upgrade campaign revalidated with fresh maintenance and recovery context.');await loadFleet();}catch(error){toast(error.message,'error');}return;
}
try{await api(`/api/v1/upgrade-campaigns/${campaign.id}/${action}`,{method:'POST',headers:{'If-Match':`"${campaign.revision}"`},body:{}});toast(`Upgrade campaign ${action} accepted.`);await loadFleet();}catch(error){toast(error.message,'error');}};

function applyOEMBranding(profile){
  if(!profile)return;
  if(profile.brandName)$('#product-brand').textContent=profile.brandName;
  if(profile.accentColor&&/^#[0-9a-f]{6}$/i.test(profile.accentColor))document.documentElement.style.setProperty('--accent',profile.accentColor);
}
async function loadOrganizationCommercial(){
  const orgId=$('#tenant-organization').value;
  if(!orgId){$('#entitlement-summary').textContent='Create an organization first.';return;}
  try{
    const entitlement=await api(`/api/v1/organizations/${orgId}/entitlement`);state.currentEntitlement=entitlement;
    $('#tenant-edition').value=entitlement.edition;
    $('#entitlement-summary').innerHTML=`<strong>${esc(entitlement.edition)}</strong> · ${esc(entitlement.maxTenants)} tenants · OEM ${entitlement.oemEnabled?'enabled':'disabled'}<br>${(entitlement.features||[]).map(esc).join(', ')}`;
  }catch(error){if(error.status===404){state.currentEntitlement=null;$('#entitlement-summary').textContent='No entitlement configured for this organization.';}else $('#entitlement-summary').textContent=error.message;}
  try{
    const profile=await api(`/api/v1/organizations/${orgId}/oem-profile`);state.currentOEMProfile=profile;
    $('#oem-brand-name').value=profile.brandName||'';$('#oem-product-title').value=profile.productTitle||'';$('#oem-support-url').value=profile.supportUrl||'';$('#oem-logo-ref').value=profile.logoObjectRef||'';$('#oem-accent-color').value=profile.accentColor||'#2557d6';$('#oem-custom-domain').value=profile.customDomain||'';$('#oem-locale').value=profile.defaultLocale||'en';applyOEMBranding(profile);
  }catch(error){if(error.status===404){state.currentOEMProfile=null;$('#oem-form').reset();$('#oem-accent-color').value='#2557d6';}else toast(error.message,'error');}
}
async function loadTenants(){
  try{
    const [organizations,projects,clusterRows,plans,tenants,recoveryCheckpoints]=await Promise.all([softApi('/api/v1/organizations',[],'organizations'),softApi('/api/v1/projects',[],'projects'),softApi('/api/v1/clusters',[],'clusters'),softApi('/api/v1/tenancy/plans',[],'tenancy plans'),softApi('/api/v1/tenants',[],'tenants'),softApi('/api/v1/recovery-checkpoints',[],'recovery checkpoints')]);
    Object.assign(state,{organizations,projects,clusters:clusterRows,tenantPlans:plans,tenants,recoveryCheckpoints});
    setOptions($('#tenant-organization'),organizations,item=>item.id,item=>`${item.displayName} · ${item.name}`,'Create an organization first');
    const orgId=$('#tenant-organization').value;
    const visibleProjects=projects.filter(project=>!orgId||project.organizationId===orgId);
    setOptions($('#tenant-project'),visibleProjects,item=>item.id,item=>`${item.displayName} · ${item.name}`,'Create a project first');
    const projectId=$('#tenant-project').value;
    const clusters=clusterRows.map(row=>row.cluster||row).filter(cluster=>!projectId||cluster.projectId===projectId);
    setOptions($('#tenant-cluster'),clusters,item=>item.id,item=>`${item.displayName} · ${item.kubernetesVersion||'version pending'}`,'Connect a cluster first');
    const planValues=Array.isArray(plans)?plans:Object.values(plans||{});
    setOptions($('#tenant-plan'),planValues,item=>item.name,item=>`${item.name} · CPU ${item.quota?.['requests.cpu']||'—'} · RAM ${item.quota?.['requests.memory']||'—'} · ${item.storage?.requestQuota||'—'} storage · ${item.backup?.provider||'no backup'}`,'No tenant plans');
    prerequisite($('#tenants-prerequisite'),organizations.length>0&&visibleProjects.length>0,'An organization and project are required before tenant provisioning.','workspace','Create workspace records');
    setIntrinsicDisabled($('#tenant-form').querySelector('button[type="submit"]'), !projectId||!clusters.length||!planValues.length);
    const visibleTenants=tenants.filter(item=>!projectId||item.projectId===projectId);
    const tenantRows=latest(visibleTenants).map(item=>{
      const approvalPending=['RESIZE_AWAITING_APPROVAL','DELETE_AWAITING_APPROVAL'].includes(item.state),canDelete=['ACTIVE','SUSPENDED','FAILED','DELETE_AWAITING_APPROVAL','DELETE_QUEUED'].includes(item.state);
      const actions=`<div class="row-actions">${item.state==='ACTIVE'?`<button type="button" class="secondary small-button" data-tenant-action="resize" data-id="${esc(item.id)}">Resize</button><button type="button" class="secondary small-button" data-tenant-action="suspend" data-id="${esc(item.id)}">Suspend</button>`:''}${item.state==='SUSPENDED'?`<button type="button" class="primary small-button" data-tenant-action="resume" data-id="${esc(item.id)}">Resume</button>`:''}${approvalPending?approvalControl(item,'Approve tenant change',`data-tenant-action="approve" data-id="${esc(item.id)}"`):''}${item.state==='FAILED'&&item.pendingAction!=='DELETE'?`<button type="button" class="primary small-button" data-tenant-action="retry" data-id="${esc(item.id)}">Retry</button>`:''}${canDelete?`<button type="button" class="danger small-button" data-tenant-action="delete" data-id="${esc(item.id)}">${['DELETE_AWAITING_APPROVAL','DELETE_QUEUED'].includes(item.state)?'Recovery':'Delete'}</button>`:''}<button type="button" class="secondary small-button" data-tenant-action="inspect" data-id="${esc(item.id)}">Inspect</button></div>`;
      return tableRow([
        tableCell(`<span class="cell-title">${esc(item.displayName)}</span><span class="cell-meta technical">${esc(item.namespace)}</span>`),
        tableCell(`${badge(item.state)}${item.pendingAction?`<span class="cell-meta">${esc(item.pendingAction)}</span>`:''}`,'status-cell'),
        tableCell(`<span class="cell-title">${esc(item.planName||'—')}</span>${item.pendingPlanName?`<span class="cell-meta">→ ${esc(item.pendingPlanName)}</span>`:''}`),
        tableCell(`<span class="technical">${esc(item.clusterId)}</span>`),
        tableCell(`<span class="cell-title">${esc(item.storagePolicy?.storageClass||'—')}</span><span class="cell-meta">${item.backupPolicy?.provider?`${esc(item.backupPolicy.provider)} · ${esc(item.backupPolicy.schedule)}`:'backup not configured'}</span>`),
        tableCell(`${esc(item.taskAttempt||0)}`,'numeric'),
        tableCell(actions,'actions-cell')
      ]);
    });
    $('#tenant-grid').innerHTML=dataTable('Tenant environments',[{label:'Tenant / namespace'},{label:'State'},{label:'Plan'},{label:'Cluster'},{label:'Storage / backup'},{label:'Attempts',className:'numeric'},{label:'Actions'}],tenantRows,'No tenant environments','Apply an entitlement and create the first namespace tenant.',{source:'tenants'});
    await loadOrganizationCommercial();
  }catch(error){$('#tenant-grid').innerHTML=errorState(error.message);}
}
$('#tenant-organization').onchange=loadTenants;$('#tenant-project').onchange=loadTenants;
$('#entitlement-form').onsubmit=async event=>{event.preventDefault();const orgId=$('#tenant-organization').value;if(!orgId)return;const headers=state.currentEntitlement?{'If-Match':`"${state.currentEntitlement.revision}"`}:{'If-None-Match':'*'};try{await api(`/api/v1/organizations/${orgId}/entitlement`,{method:'PUT',headers,body:{edition:$('#tenant-edition').value}});toast('Entitlement applied.');await loadOrganizationCommercial();}catch(error){toast(error.message,'error');}};
$('#oem-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const orgId=$('#tenant-organization').value;if(!orgId)return;const payload={brandName:$('#oem-brand-name').value.trim(),productTitle:$('#oem-product-title').value.trim(),supportUrl:$('#oem-support-url').value.trim(),logoObjectRef:$('#oem-logo-ref').value.trim(),accentColor:$('#oem-accent-color').value,customDomain:$('#oem-custom-domain').value.trim(),defaultLocale:$('#oem-locale').value};const headers=state.currentOEMProfile?{'If-Match':`"${state.currentOEMProfile.revision}"`}:{'If-None-Match':'*'};try{const profile=await api(`/api/v1/organizations/${orgId}/oem-profile`,{method:'PUT',headers,body:payload});applyOEMBranding(profile);toast('OEM profile saved.');}catch(error){toast(error.message,'error');}};
$('#tenant-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const project=state.projects.find(item=>item.id===$('#tenant-project').value);try{await api('/api/v1/tenants',{method:'POST',headers:{'Idempotency-Key':idempotency('tenant')},body:{projectId:project.id,clusterId:$('#tenant-cluster').value,name:$('#tenant-name').value.trim(),displayName:$('#tenant-display-name').value.trim(),planName:$('#tenant-plan').value}});toast('Tenant provisioning queued.');$('#tenant-name').value='';$('#tenant-display-name').value='';await loadTenants();}catch(error){toast(error.message,'error');}};
$('#tenant-grid').onclick=async event=>{
  const button=event.target.closest('[data-tenant-action]');if(!button)return;
  const item=state.tenants.find(value=>value.id===button.dataset.id);if(!item)return;
  const action=button.dataset.tenantAction;
  if(action==='inspect'){
    showDetails(item.displayName,`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(item.id)}</dd><dt>State</dt><dd>${badge(item.state)}</dd><dt>Namespace</dt><dd class="technical">${esc(item.namespace)}</dd><dt>Plan</dt><dd>${esc(item.planName)}</dd><dt>Pending plan</dt><dd>${esc(item.pendingPlanName||'—')}</dd><dt>Desired digest</dt><dd class="technical">${esc(item.desiredDigest)}</dd><dt>Pending desired</dt><dd class="technical">${esc(item.pendingDesiredDigest||'—')}</dd><dt>Observed digest</dt><dd class="technical">${esc(item.observedDigest||'—')}</dd><dt>Storage class</dt><dd class="technical">${esc(item.storagePolicy?.storageClass||'—')}</dd><dt>Storage quota</dt><dd class="technical">${esc(item.storagePolicy?.requestQuota||'—')}</dd><dt>Max PVC</dt><dd class="technical">${esc(item.storagePolicy?.maxPVCSize||'—')}</dd><dt>Backup policy</dt><dd>${esc(item.backupPolicy?.provider||'—')} · <span class="technical">${esc(item.backupPolicy?.schedule||'—')}</span> · retain ${esc(item.backupPolicy?.retention||'—')}</dd><dt>Network security</dt><dd>${item.securityPolicy?.defaultDenyIngress&&item.securityPolicy?.defaultDenyEgress?'Default deny ingress + egress':'—'} · DNS ${item.securityPolicy?.allowDNS?'allowed':'blocked'}</dd><dt>Pod Security</dt><dd>${esc(item.securityPolicy?.podSecurityLevel||'—')}</dd><dt>Evidence seal</dt><dd class="technical">${esc(item.evidenceDigest||'—')}</dd><dt>Evidence artifacts</dt><dd>${(item.evidence||[]).map(ev=>`${badge(ev.status)} ${esc(ev.key)} · ${esc(ev.authority)} · <span class="technical">${esc(shortDigest(ev.digest||''))}</span>`).join('<br>')||'—'}</dd><dt>Recovery checkpoint</dt><dd class="technical">${esc(item.recoveryCheckpointId||'—')}</dd><dt>Destructive operation</dt><dd class="technical">${esc(item.destructiveOperationId||'—')}</dd><dt>Pending action</dt><dd>${esc(item.pendingAction||'—')}</dd><dt>Requested by</dt><dd>${esc(item.requestedBy||'—')}</dd><dt>Approved by</dt><dd>${esc(item.approvedBy||'—')}</dd><dt>Error</dt><dd>${esc(item.lastError||'—')}</dd></dl>`);return;
  }
  const headers={'If-Match':`"${item.revision}"`};let payload={};
  if(action==='resize'){
    const plans=(Array.isArray(state.tenantPlans)?state.tenantPlans:Object.values(state.tenantPlans||{})).filter(plan=>plan.name!==item.planName);
    const values=await askFields('Resize tenant service',[{name:'planName',label:'Target plan',type:'select',options:plans.map(plan=>({value:plan.name,label:`${plan.name} · CPU ${plan.quota?.['requests.cpu']||'—'} · RAM ${plan.quota?.['requests.memory']||'—'}`}))}], 'Request resize');
    if(!values)return;payload={planName:values.planName};
  }
  if(action==='delete'){
    if(!await confirmAction('Protected delete tenant environment',`Delete namespace ${item.namespace}? A verified recovery checkpoint and a different platform-admin approval are required before execution.`,true))return;
    const checkpointId=await chooseDestructiveRecoveryCheckpoint('Bind verified backup before tenant delete',item.projectId,item.clusterId);if(!checkpointId)return;
    headers['X-Confirm-Delete']='delete-tenant-namespace';payload={recoveryCheckpointId:checkpointId};
  }
  if(action==='approve'&&!await confirmAction('Approve tenant change',`Approve ${String(item.pendingAction||'change').toLowerCase()} for ${item.displayName}?`))return;
  if(action==='suspend'&&!await confirmAction('Suspend tenant',`Suspend workloads in ${item.namespace}?`))return;
  try{
    await api(`/api/v1/tenants/${item.id}/${action}`,{method:'POST',headers,body:payload});
    const message=action==='approve'?'Tenant change approved.':action==='resize'?'Tenant resize is awaiting approval.':action==='delete'?'Protected delete is awaiting approval.':`Tenant ${action} queued.`;
    toast(message);await loadTenants();
  }catch(error){toast(error.message,'error');}
};



function syncAIResourceOptions(){
  const projectId=$('#ai-project')?.value||'';
  const type=$('#ai-resource-type')?.value||'operation';
  const select=$('#ai-resource'); if(!select)return;
  const items=type==='cluster'
    ? state.clusters.map(row=>row.cluster||row).filter(item=>item.projectId===projectId).map(item=>({value:item.id,label:`${item.displayName||item.name||item.id} · ${item.connectionState||'UNKNOWN'}`}))
    : state.operations.filter(item=>item.projectId===projectId).map(item=>({value:item.id,label:`${item.kind||'operation'} · ${item.state||'UNKNOWN'} · ${item.id}`}));
  setOptions(select,items,item=>item.value,item=>item.label,'Select authoritative context');
}

function renderAILatestDiagnosis(){
  const target=$('#ai-diagnosis-result'); if(!target)return;
  const value=state.aiLatestDiagnosis;
  if(!value){target.innerHTML='<p>No AI diagnosis has been requested in this session.</p>';return;}
  const d=value.diagnosis||{},run=value.run||{};
  target.innerHTML=`<div class="resource-details">${detailRow('Classification',badge(d.classification||'unknown'))}${detailRow('Confidence',`${esc(d.confidence??0)}%`)}${detailRow('Owner',esc(d.owner||'—'))}${detailRow('Provider',`${esc(run.provider||'—')} · ${esc(run.model||'—')}`)}${detailRow('Redactions',esc(run.redactionCount||0))}${detailRow('Input tokens',esc(run.inputTokens||0))}${detailRow('Cached tokens',esc(run.cachedTokens||0))}${detailRow('Output tokens',esc(run.outputTokens||0))}</div><div class="prerequisite"><strong>Summary</strong><p>${esc(d.summary||'—')}</p></div>${(d.recommendedChecks||[]).length?`<details open><summary>Recommended deterministic checks</summary><ul>${d.recommendedChecks.map(item=>`<li>${esc(item)}</li>`).join('')}</ul></details>`:''}<div class="inline-summary"><strong>Proposed direction:</strong> ${esc(d.recommendedFix||'—')}</div>`;
}

function renderAIRuntimeAndAccess(){
  const policy=state.aiPolicy||{},guide=state.aiGuide||{},mcp=guide.mcp||{};
  const runtime=$('#ai-runtime-details');
  if(runtime){
    const last=latest(state.aiRuns||[])[0];
    runtime.innerHTML=`<div class="resource-details">${detailRow('Runtime authority',policy.runtimeAuthority||'—',true)}${detailRow('Configuration',policy.enabled?badge('CONFIGURED'):badge('DISABLED'))}${detailRow('Provider',esc(policy.provider||'none'))}${detailRow('Model',esc(policy.model||'—'))}${detailRow('Input ceiling',`${esc(policy.maxInputBytes||0)} bytes`)}${detailRow('Output ceiling',`${esc(policy.maxOutputTokens||0)} tokens`)}${detailRow('Redaction',policy.redactionRequired?'REQUIRED':'UNKNOWN')}${detailRow('Latest durable advisory',last?formatDate(last.createdAt):'None recorded')}</div><div class="inline-summary"><strong>Authority:</strong> advisory only · no PASS / Physical PASS · no direct mutation. Provider reachability is evaluated only by an actual bounded diagnosis request.</div>`;
  }
  const access=$('#ai-mcp-access');
  if(access){
    const tools=mcp.tools||[];
    access.innerHTML=`<div class="resource-details">${detailRow('Endpoint',mcp.path||'/mcp',true)}${detailRow('Protocol',mcp.protocol||'2026-07-28',true)}${detailRow('Transport',mcp.transport||'streamable-http')}${detailRow('Read scope',mcp.permission||'mcp.read',true)}${detailRow('Diagnosis scope','ai.diagnose',true)}${detailRow('Mutation tools',(mcp.mutatingTools||[]).length?String(mcp.mutatingTools.length):'NONE')}</div><details open><summary>Read-only tools (${tools.length})</summary><div class="activity-list">${tools.map(tool=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">✓</span><div><strong class="technical">${esc(tool)}</strong><small>Authenticated capability context · project authorization is rechecked for project resources.</small></div></div>${badge('READ ONLY')}</div>`).join('')}</div></details>`;
  }
}

function renderAIUsageSummary(){
  const runs=state.aiRuns||[];
  const totals=runs.reduce((acc,run)=>{acc.input+=Number(run.inputTokens||0);acc.cached+=Number(run.cachedTokens||0);acc.output+=Number(run.outputTokens||0);acc.redactions+=Number(run.redactionCount||0);return acc;},{input:0,cached:0,output:0,redactions:0});
  const totalTokens=totals.input+totals.output;
  const cachePct=totals.input>0?Math.round((totals.cached/totals.input)*100):0;
  const last=latest(runs)[0];
  const target=$('#ai-usage-summary'); if(!target)return;
  target.innerHTML=[
    ['Durable runs',runs.length,'successful advisory records'],
    ['Tokens',totalTokens,`${totals.input} input · ${totals.output} output`],
    ['Cached',`${cachePct}%`,`${totals.cached} cached input tokens`],
    ['Redactions',totals.redactions,'secret-like values removed before egress'],
    ['Latest run',last?formatDate(last.createdAt):'—',last?`${last.provider||'—'} · ${last.model||'—'}`:'No durable advisory yet']
  ].map(([label,value,detail])=>`<article class="metric-card"><strong>${esc(value)}</strong><span>${esc(label)}</span><small>${esc(detail)}</small></article>`).join('');
}

function aiRunProjectName(id){return state.projects.find(project=>project.id===id)?.displayName||state.projects.find(project=>project.id===id)?.name||id||'—';}

function renderAIRunHistory(){
  const filter=$('#ai-run-project-filter')?.value||'';
  const values=filter?(state.aiRuns||[]).filter(run=>run.projectId===filter):(state.aiRuns||[]);
  const rows=latest(values).map(run=>tableRow([
    tableCell(`<span class="cell-title">${esc(run.purpose)}</span><span class="cell-meta technical">${esc(run.id)}</span>`),
    tableCell(`<span class="cell-title">${esc(aiRunProjectName(run.projectId))}</span><span class="cell-meta">${esc(run.linkedResourceType||'unlinked')} · <span class="technical">${esc(run.linkedResourceId||'—')}</span></span>`),
    tableCell(`<span class="cell-title">${esc(run.provider||'—')}</span><span class="cell-meta">${esc(run.model||'—')}</span>`),
    tableCell(`${esc(run.inputTokens||0)} / ${esc(run.cachedTokens||0)} / ${esc(run.outputTokens||0)}`,'numeric'),
    tableCell(`${esc(run.redactionCount||0)}`,'numeric'),
    tableCell(`<span class="technical">${shortDigest(run.contextDigest)}</span><span class="cell-meta technical">${shortDigest(run.outputDigest)}</span>`),
    tableCell(formatDate(run.createdAt),'timestamp',run.createdAt||''),
    tableCell(`<button class="secondary compact-button" type="button" data-ai-run-inspect="${esc(run.id)}">Inspect</button>`,'actions-cell')
  ]));
  $('#ai-run-grid').innerHTML=dataTable('Durable AI runs',[{label:'Purpose / run'},{label:'Project / linked authority'},{label:'Provider / model'},{label:'Tokens in / cached / out',className:'numeric'},{label:'Redactions',className:'numeric'},{label:'Context / output digest'},{label:'Created',className:'timestamp'},{label:'Evidence',sortable:false,className:'actions-cell'}],rows,'No AI runs','AI is optional. Deterministic platform workflows remain available without a configured model.',{key:'ai-runs'});
  restoreDataTableSortPreferences($('#ai'));
}

function inspectAIRun(id){
  const run=(state.aiRuns||[]).find(item=>item.id===id); if(!run)return;
  const output=typeof run.output==='string'?run.output:JSON.stringify(run.output||{},null,2);
  showDetails(`AI advisory evidence · ${run.id}`,`<div class="warning-banner"><strong>Advisory only</strong><p>This record cannot authorize a mutation, deterministic PASS or Exact-SHA Physical PASS.</p></div><div class="resource-details">${detailRow('Project',esc(aiRunProjectName(run.projectId)))}${detailRow('Purpose',esc(run.purpose||'—'))}${detailRow('Provider / model',`${esc(run.provider||'—')} · ${esc(run.model||'—')}`)}${detailRow('Prompt ID',esc(run.promptId||'—'),true)}${detailRow('Linked authority',`${esc(run.linkedResourceType||'none')} · ${esc(run.linkedResourceId||'—')}`)}${detailRow('Redactions',esc(run.redactionCount||0))}${detailRow('Tokens',`${esc(run.inputTokens||0)} in · ${esc(run.cachedTokens||0)} cached · ${esc(run.outputTokens||0)} out`)}${detailRow('Prompt digest',esc(run.promptDigest||'—'),true)}${detailRow('Context digest',esc(run.contextDigest||'—'),true)}${detailRow('Output digest',esc(run.outputDigest||'—'),true)}${detailRow('Request digest',esc(run.requestDigest||'—'),true)}${detailRow('Created',formatDate(run.createdAt))}</div><details open><summary>Structured advisory output</summary><pre class="code-block technical" dir="ltr">${esc(output)}</pre></details>`);
}

async function loadAI(){
  try{
    const [policy,guide,projects,operations,clusters,runs]=await Promise.all([
      softApi('/api/v1/ai/policy',{},'AI policy'), softApi('/api/v1/lab/guide',{},'lab guide'), softApi('/api/v1/projects',[],'projects'), softApi('/api/v1/operations?limit=200',[],'operations'), softApi('/api/v1/clusters',[],'clusters'), softApi('/api/v1/ai/runs',[],'AI runs')
    ]);
    state.aiPolicy=policy; state.aiGuide=guide; state.projects=projects; state.operations=operations; state.clusters=clusters; state.aiRuns=runs;
    $('#ai-policy-summary').innerHTML=[
      ['Runtime',policy.enabled?'ENABLED':'DISABLED',policy.provider||'none'],['Model',policy.model||'—','provider-selected'],['Input budget',policy.maxInputBytes||0,'bytes after redaction'],['Output budget',policy.maxOutputTokens||0,'tokens max'],['Authority','ADVISORY ONLY','PASS / Physical PASS: never']
    ].map(([label,value,detail])=>`<article class="metric-card"><strong>${esc(value)}</strong><span>${esc(label)}</span><small>${esc(detail)}</small></article>`).join('');
    const banner=$('#ai-runtime-banner');
    if(banner){banner.hidden=!!policy.enabled;banner.innerHTML=policy.enabled?'':'<strong>AI runtime disabled</strong><p>No model provider is configured. Deterministic platform, Lab and certification workflows remain available; AI diagnosis is intentionally unavailable.</p>';}
    const diagnosisButton=$('#ai-diagnosis-form button[type="submit"]'); if(diagnosisButton)diagnosisButton.disabled=!policy.enabled;
    const projectSelect=$('#ai-project'); const selected=projectSelect?.value||'';
    setOptions(projectSelect,projects.map(p=>({value:p.id,label:p.displayName||p.name||p.id})),item=>item.value,item=>item.label,'Select project');
    if(selected&&projects.some(p=>p.id===selected))projectSelect.value=selected;
    const historyFilter=$('#ai-run-project-filter'),historySelected=historyFilter?.value||'';
    if(historyFilter){historyFilter.innerHTML='<option value="">All accessible projects</option>'+projects.map(p=>`<option value="${esc(p.id)}">${esc(p.displayName||p.name||p.id)}</option>`).join('');if(historySelected&&projects.some(p=>p.id===historySelected))historyFilter.value=historySelected;}
    syncAIResourceOptions();
    renderAIRuntimeAndAccess(); renderAIUsageSummary(); renderAIRunHistory(); renderAILatestDiagnosis();
  }catch(error){toast(error.message,'error');}
}

$('#ai-project').onchange=syncAIResourceOptions;
$('#ai-resource-type').onchange=syncAIResourceOptions;
$('#ai-run-project-filter').onchange=renderAIRunHistory;
$('#ai-run-grid').onclick=event=>{const button=event.target.closest('[data-ai-run-inspect]');if(button)inspectAIRun(button.dataset.aiRunInspect);};
$('#ai-diagnosis-form').onsubmit=async event=>{
  event.preventDefault(); if(!event.currentTarget.reportValidity())return;
  const projectId=$('#ai-project').value,resourceId=$('#ai-resource').value,question=$('#ai-question').value.trim(),type=$('#ai-resource-type').value;
  if(!projectId||!resourceId||!question){toast('Select authoritative context and enter a concrete question.','error');return;}
  const body={projectId,question}; body[type==='cluster'?'clusterId':'operationId']=resourceId;
  try{state.aiLatestDiagnosis=await api('/api/v1/ai/diagnose',{method:'POST',headers:{'Idempotency-Key':idempotency('ai-diagnose')},body});renderAILatestDiagnosis();const runs=await softApi('/api/v1/ai/runs',[],'AI runs');state.aiRuns=runs;renderAIUsageSummary();renderAIRunHistory();toast('AI advisory recorded. No action was executed.');}catch(error){toast(error.message,'error');}
};

async function loadLab(){
  try{
    const [guide,targetArchitecture]=await Promise.all([softApi('/api/v1/lab/guide',{},'lab guide'),softApi('/api/v1/target-architecture-model',{},'target architecture')]);
    if(guide.authority && guide.authority!=='LAB_CERTIFICATION_MATRIX_V1') throw new Error('Unexpected lab guide authority.');
    state.labGuide=guide;
    const tiers=guide.serverTiers||[];const matrix=guide.matrix||[];const ai=guide.aiPolicy||{};const mcp=guide.mcp||{};
    $('#lab-summary').innerHTML=[
      ['Authority',guide.authority||'unavailable',`${matrix.length} deterministic matrix rows`],
      ['Server tiers',tiers.length,tiers.map(item=>item.physicalServers).join(' / ')||'—'],
      ['AI packet',`${Math.round((ai.maxFailurePacketBytes||0)/1024)} KiB max`,`${ai.maxOutputTokens||0} output tokens max`],
      ['MCP',mcp.protocol||mcp.protocolVersion||'unavailable',`${mcp.transport||'—'} · ${mcp.defaultAccess==='read-only'?'read-only':'mutation-capable'}`]
    ].map(([label,value,detail])=>`<article class="metric-card"><strong>${esc(value)}</strong><span>${esc(label)}</span><small>${esc(detail)}</small></article>`).join('');
    const tierRows=tiers.map(item=>tableRow([
      tableCell(`<span class="cell-title">${esc(item.displayName||item.name||item.id)}</span><span class="cell-meta technical">${esc(item.id)}</span>`),
      tableCell(String(item.physicalServers||0),'numeric',item.physicalServers||0),
      tableCell((item.roles||[]).map(role=>`<span class="technical">${esc(role)}</span>`).join('<br>')),
      tableCell(`${esc(item.purpose||item.description||'—')}${(item.resourceSummary||[]).length?`<span class="cell-meta">${(item.resourceSummary||[]).map(line=>esc(line)).join('<br>')}</span>`:''}`)
    ]));
    $('#lab-server-tiers').innerHTML=dataTable('Lab server tiers',[{label:'Tier'},{label:'Servers',className:'numeric'},{label:'Required roles'},{label:'Purpose'}],tierRows,'No server tiers','The canonical lab authority did not return server requirements.',{key:'lab-server-tiers'});
    const matrixRows=matrix.map(row=>tableRow([
      tableCell(`<span class="cell-title technical">${esc(row.id)}</span><span class="cell-meta">${esc(row.name)}</span>`),
      tableCell(`<span class="technical">${esc(row.serverTier)}</span>`),
      tableCell(esc(row.phase||'—')),
      tableCell(row.destructive?badge('DESTRUCTIVE'):badge('READ/SAFE'),'status-cell'),
      tableCell(row.aiEligible?badge('AI ON FAILURE'):badge('DETERMINISTIC'),'status-cell'),
      tableCell(`${badge(row.automationStatus||'UNKNOWN')}<span class="cell-meta">${esc(row.automationDetail||'—')}</span>`,'status-cell'),
      tableCell((row.actions||[]).map(action=>`<span class="cell-meta">${esc(action)}</span>`).join(''))
    ]));
    $('#lab-matrix').innerHTML=dataTable('Physical certification matrix',[{label:'Test'},{label:'Server tier'},{label:'Phase'},{label:'Safety'},{label:'Diagnosis'},{label:'Automation'},{label:'Actions'}],matrixRows,'No matrix rows','The lab matrix is unavailable.',{key:'lab-matrix'});
    const roadmap=targetArchitecture?.programRoadmap||{},tracks=roadmap.tracks||[],current=(roadmap.phases||[]).find(item=>item.id===roadmap.currentPhase);
    const trackRows=tracks.map(track=>tableRow([tableCell(`<span class="cell-title">${esc(track.title||track.id)}</span><span class="cell-meta technical">${esc(track.id)}</span>`),tableCell(esc(track.objective||'—')),tableCell((track.requirements||[]).map(item=>`<span class="cell-meta">${esc(item)}</span>`).join(''))]));
    $('#lab-program-tracks').innerHTML=`<div class="inline-summary"><strong>${esc(roadmap.authority||'unavailable')}</strong> · current <span class="technical">${esc(roadmap.currentPhase||'—')}</span>${current?` · ${badge(current.status||'UNKNOWN')}`:''} · ${esc((roadmap.globalGuardrails||[]).length)} global guardrails</div>${dataTable('Cross-cutting program tracks',[{label:'Track'},{label:'Objective'},{label:'Required in every later phase'}],trackRows,'No program tracks','The canonical program-track authority is unavailable.',{key:'lab-program-tracks'})}`;
    $('#lab-ai-policy').innerHTML=`<div class="resource-details">${detailRow('Invocation',ai.defaultMode||'failure-only')}${detailRow('Failure packet',`${ai.defaultFailurePacketBytes||0} default / ${ai.maxFailurePacketBytes||0} max bytes`)}${detailRow('Output budget',`${ai.defaultOutputTokens||0} default / ${ai.maxOutputTokens||0} max tokens`)}${detailRow('Can decide PASS','NO')}${detailRow('Can decide Physical PASS','NO')}</div><details open><summary>Supported adapters</summary><div class="activity-list">${(ai.providers||[]).map(provider=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">•</span><div><strong class="technical">${esc(provider.id||provider)}</strong><small>${esc(provider.use||provider.role||provider.description||'bounded diagnosis / repair adapter')}</small></div></div></div>`).join('')}</div></details>`;
    $('#lab-mcp').innerHTML=`<div class="resource-details">${detailRow('Endpoint',mcp.path||mcp.endpoint||'/mcp')}${detailRow('Protocol',mcp.protocol||mcp.protocolVersion||'—')}${detailRow('Transport',mcp.transport||'—')}${detailRow('Authority',mcp.defaultAccess==='read-only'?'READ ONLY':'MUTATING')}</div><details open><summary>Exposed tools</summary><div class="activity-list">${(mcp.tools||[]).map(tool=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">✓</span><div><strong class="technical">${esc(tool.name||tool)}</strong><small>${esc(tool.description||'authoritative read-only resource')}</small></div></div>${badge('READ ONLY')}</div>`).join('')}</div></details><p class="inline-summary">External clients must authenticate through the normal Platform API boundary and send <span class="technical">MCP-Protocol-Version: ${esc(mcp.protocol||mcp.protocolVersion||'2026-07-28')}</span>.</p>`;
    restoreDataTableSortPreferences($('#lab'));
  }catch(error){toast(error.message,'error');}
}

async function loadOperations(){
  try{
    const securityAllowed=mayAdministerIdentityAuthority();
    const [summary,operations,audit,securityAudit]=await Promise.all([softApi('/api/v1/control-plane/summary',{},'control-plane summary'),softApi('/api/v1/operations?limit=200',[],'operations'),softApi('/api/v1/audit-events?limit=100',[],'audit'),securityAllowed?softApi('/api/v1/security-audit-events?limit=200',[],'security audit'):Promise.resolve([])]);
    Object.assign(state,{summary,operations,audit,securityAudit});
    $('#control-plane-summary').innerHTML=[['Authority',summary.authorityBackend,'authoritative store'],['Operations',summary.operations,`${summary.evidence} evidence records`],['Outbox pending',summary.unpublishedOutbox,'durable events'],['Audit events',summary.auditEvents,'append-only history']].map(([label,value,detail])=>`<article class="metric-card"><strong>${esc(value)}</strong><span>${esc(label)}</span><small>${esc(detail)}</small></article>`).join('');
    const operationRows=latest(operations).map(op=>{
      const flags=[op.retryExhausted?badge('RETRY EXHAUSTED'):'',op.recoveryCheckpointId?badge('RECOVERY BOUND'):'',op.compensationPlanDigest?badge('COMPENSATION BOUND'):'',op.state==='NEEDS_OPERATOR'?badge('OPERATOR REQUIRED'):''].join(' ');
      const actions=`<div class="row-actions"><button type="button" class="secondary small-button" data-operation-id="${esc(op.id)}">Inspect</button><button type="button" class="secondary small-button" data-operation-bundle="${esc(op.id)}">Bundle</button>${!['SUCCEEDED','ROLLED_BACK','CANCELLED'].includes(op.state)?`<button type="button" class="danger small-button" data-operation-cancel="${esc(op.id)}">Cancel</button>`:''}</div>`;
      return tableRow([
        tableCell(`<span class="cell-title">${esc(op.kind)}</span><span class="cell-meta technical">${esc(op.id)}</span>`),
        tableCell(`${badge(op.state)}${flags?`<span class="cell-meta">${flags}</span>`:''}`,'status-cell'),
        tableCell(`<span class="cell-title technical">${esc(op.targetRef)}</span><span class="cell-meta">${esc(op.class||'MUTATING')} · risk ${esc(op.risk||'—')}</span>`),
        tableCell(`${esc(op.attempt||0)} / ${esc(op.retryPolicy?.maxAttempts||'—')}`,'numeric'),
        tableCell(formatDate(op.updatedAt),'timestamp',op.updatedAt||''),
        tableCell(actions,'actions-cell')
      ]);
    });
    $('#operation-grid').innerHTML=dataTable('Durable operations',[{label:'Operation'},{label:'State'},{label:'Target'},{label:'Attempt',className:'numeric'},{label:'Updated',className:'timestamp'},{label:'Actions'}],operationRows,'No durable operations','Product workflow operations will appear here.',{source:'operations'});
    const auditRows=latest(audit).map(item=>tableRow([
      tableCell(`<span class="cell-title">${esc(item.action)}</span><span class="cell-meta">revision ${esc(item.revision)}</span>`),
      tableCell(`<span class="cell-title">${esc(item.resourceType)}</span><span class="cell-meta technical">${esc(item.resourceId)}</span>`),
      tableCell(`<span class="technical">${esc(item.actorId)}</span>`),
      tableCell(formatDate(item.occurredAt),'timestamp',item.occurredAt||'')
    ]));
    $('#audit-grid').innerHTML=dataTable('Audit trail',[{label:'Action'},{label:'Resource'},{label:'Actor'},{label:'Occurred',className:'timestamp'}],auditRows,'No audit events','Resource mutations will be recorded here.',{source:'audit'});
    const securityPanel=$('#security-audit-panel');securityPanel.hidden=!securityAllowed;
    if(securityAllowed){
      const rows=[...securityAudit].sort((a,b)=>Number(b.sequence)-Number(a.sequence));let linked=true;const asc=[...securityAudit].sort((a,b)=>Number(a.sequence)-Number(b.sequence));for(let i=1;i<asc.length;i++){if(Number(asc[i].sequence)!==Number(asc[i-1].sequence)+1||String(asc[i].previousDigest||'')!==String(asc[i-1].digest||'')){linked=false;break;}}
      $('#security-audit-summary').innerHTML=`<strong>${esc(rows[0]?.methodVersion||'IMMUTABLE_AUTHN_AUTHZ_AUDIT_V1')}</strong> · ${esc(rows.length)} loaded · hash-chain ${linked?'linked':'verification warning'} · allow decisions are fail-closed on audit persistence`;
      const securityRows=rows.slice(0,100).map(item=>tableRow([
        tableCell(`<span class="cell-title">${esc(item.category)}</span><span class="cell-meta">${esc(item.reasonCode||'—')}</span>`),
        tableCell(badge(item.decision),'status-cell'),
        tableCell(`<span class="cell-title technical">${esc(item.actorId)}</span><span class="cell-meta">${esc(item.authentication||'—')} · ${esc(item.effectiveRole||'—')}</span>`),
        tableCell(`<span class="cell-title technical">${esc(item.method||'')} ${esc(item.path||'')}</span><span class="cell-meta technical">${esc(item.scopeType||'—')}:${esc(item.scopeId||'—')}</span>`),
        tableCell(`#${esc(item.sequence)}`,'numeric'),
        tableCell(formatDate(item.occurredAt),'timestamp',item.occurredAt||'')
      ]));
      $('#security-audit-grid').innerHTML=dataTable('Security audit events',[{label:'Decision context'},{label:'Decision'},{label:'Actor'},{label:'Request / scope'},{label:'Seq',className:'numeric'},{label:'Occurred',className:'timestamp'}],securityRows,'No security audit events','Authentication and authorization decisions will appear here.',{source:'security audit'});
    }
  }catch(error){$('#operation-grid').innerHTML=errorState(error.message);$('#audit-grid').innerHTML=errorState(error.message);if($('#security-audit-grid'))$('#security-audit-grid').innerHTML=errorState(error.message);}
}
$('#operation-grid').onclick=async event=>{const bundle=event.target.closest('[data-operation-bundle]');if(bundle){try{await downloadSupportBundle({profile:'operation-diagnostics',operationId:bundle.dataset.operationBundle});toast('Operation support bundle downloaded.');}catch(error){toast(error.message,'error');}return;}const cancel=event.target.closest('[data-operation-cancel]');if(cancel){const op=state.operations.find(item=>item.id===cancel.dataset.operationCancel);if(!op)return;if(!await confirmAction('Cancel operation safely',`Request cancellation for ${op.kind}? In-flight work is drained to a safe boundary before final cancellation.`))return;try{await api(`/api/v1/operations/${op.id}/cancel`,{method:'POST',headers:{'If-Match':`"${op.revision}"`},body:{reason:'operator requested safe cancellation from console'}});toast('Cancellation requested.');await loadOperations();}catch(error){toast(error.message,'error');}return;}const button=event.target.closest('[data-operation-id]');if(!button)return;try{const view=await api(`/api/v1/operations/${button.dataset.operationId}`),op=view.operation;showDetails(op.kind,`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(op.id)}</dd><dt>State</dt><dd>${badge(op.state)}</dd><dt>Class</dt><dd>${badge(op.class||'MUTATING')}</dd><dt>Target</dt><dd class="technical">${esc(op.targetRef)}</dd><dt>Risk</dt><dd>${esc(op.risk)}</dd><dt>Attempt</dt><dd>${esc(op.attempt||0)} / ${esc(op.retryPolicy?.maxAttempts||'—')}</dd><dt>Retry classes</dt><dd>${esc((op.retryPolicy?.retryableClasses||[]).join(', ')||'—')}</dd><dt>Backoff</dt><dd>${esc(op.retryPolicy?.initialBackoffSeconds||'—')}s → max ${esc(op.retryPolicy?.maxBackoffSeconds||'—')}s</dd><dt>Next attempt</dt><dd>${formatDate(op.nextAttemptAt)}</dd><dt>Last failure class</dt><dd>${esc(op.lastFailureClass||'—')}</dd><dt>Recovery checkpoint</dt><dd class="technical">${esc(op.recoveryCheckpointId||'—')}</dd><dt>Recovery evidence</dt><dd class="technical">${esc(op.recoveryEvidenceDigest||'—')}</dd><dt>Compensation plan</dt><dd class="technical">${esc(op.compensationPlanDigest||'—')}</dd><dt>Compensation steps</dt><dd>${esc(op.compensationStepCount||0)} · cursor ${esc(op.compensationCursor||0)}</dd><dt>Compensation failure step</dt><dd class="technical">${esc(op.compensationFailureStep||'—')}</dd><dt>Cancellation</dt><dd>${esc(op.cancelReason||'—')}</dd><dt>Actor</dt><dd>${esc(op.actorId)}</dd><dt>Desired revision</dt><dd class="technical">${esc(op.desiredRevision)}</dd><dt>Error</dt><dd>${esc(op.lastError||'—')}</dd></dl><div class="detail-section"><h3>Steps</h3><div class="timeline">${(view.steps||[]).map(step=>`<div class="timeline-step ${step.state==='SUCCEEDED'?'success':step.state==='FAILED'?'failed':''}"><span class="timeline-dot">${step.state==='SUCCEEDED'?'✓':step.state==='FAILED'?'!':'○'}</span><div><h4>${esc(step.stepKey)}</h4><p>${esc(step.state)} · attempt ${esc(step.attempt)}${step.lastError?` · ${esc(step.lastError)}`:''}</p></div></div>`).join('')||'<p>No operation steps.</p>'}</div></div><div class="detail-section"><h3>Compensation</h3><div class="timeline">${(view.compensation||[]).slice().sort((a,b)=>b.forwardOrder-a.forwardOrder).map(step=>`<div class="timeline-step ${step.state==='SUCCEEDED'?'success':['FAILED','MANUAL_REQUIRED'].includes(step.state)?'failed':''}"><span class="timeline-dot">${step.state==='SUCCEEDED'?'✓':['FAILED','MANUAL_REQUIRED'].includes(step.state)?'!':'↩'}</span><div><h4>${esc(step.stepKey)} · ${esc(step.strategy)}</h4><p>forward #${esc(step.forwardOrder)} · ${step.forwardCompleted?'committed':'not committed'} · compensation ${esc(step.state)} · attempt ${esc(step.attempt)}/${esc(step.maxAttempts)}${step.evidenceDigest?` · ${esc(shortDigest(step.evidenceDigest))}`:''}${step.lastError?` · ${esc(step.lastError)}`:''}</p></div></div>`).join('')||'<p>No compensation plan is bound.</p>'}</div></div><div class="detail-section"><h3>Step trace / logs & evidence</h3><div class="resource-details">${detailRow('Trace authority',view.traceMethod||'—')}${detailRow('Trace entries',(view.traces||[]).length)}${detailRow('Payload evidence',(view.evidence||[]).filter(item=>item.hasPayload).length)}</div><div class="timeline">${(view.traces||[]).map(trace=>`<div class="timeline-step ${trace.level==='ERROR'?'failed':trace.level==='WARN'?'':'success'}"><span class="timeline-dot">${trace.level==='ERROR'?'!':trace.level==='WARN'?'△':'•'}</span><div><h4>${esc(trace.phase)} · ${esc(trace.stepKey)} · attempt ${esc(trace.attempt)} · #${esc(trace.sequence)}</h4><p>${badge(trace.level)} ${esc(trace.eventType)} · ${esc(trace.message)}</p><small class="technical">trace ${esc(trace.traceKey)} · evidence ${esc(trace.evidenceId||'—')} · ${esc(shortDigest(trace.evidenceDigest||''))}</small></div></div>`).join('')||'<p>No per-step trace has been sealed.</p>'}</div></div><div class="detail-section"><h3>Evidence</h3>${(view.evidence||[]).length?`<dl class="key-value">${view.evidence.map(item=>`<dt>${esc(item.kind)}</dt><dd><span class="technical">${esc(item.digest)}</span><br>${esc(item.phase||'OPERATION')} · ${esc(item.stepKey||'operation')} · attempt ${esc(item.attempt||0)} · ${esc(item.location)} · ${item.sealed?'sealed':'unsealed'} · payload ${item.hasPayload?'available':'metadata-only'}${item.traceId?` · trace ${esc(item.traceId)}`:''}${item.hasPayload?`<br><button type="button" class="secondary small-button" data-operation-id="${esc(op.id)}" data-operation-evidence-payload="${esc(item.id)}">Inspect payload</button>`:''}</dd>`).join('')}</dl>`:'<p>No evidence attached.</p>'}</div>`);}catch(error){toast(error.message,'error');}};


function notificationOrgProjects(orgId){ return state.projects.filter(project=>project.organizationId===orgId); }
function renderNotificationEventTypes(){
  const selected=new Set($$('#notification-event-type-list input:checked').map(input=>input.value));
  $('#notification-event-type-list').innerHTML=state.notificationEventTypes.length?state.notificationEventTypes.map(item=>`<label class="activity-item"><span class="activity-main"><input type="checkbox" data-notification-event-type value="${esc(item.eventType)}"${selected.has(item.eventType)?' checked':''}><span><strong class="technical">${esc(item.eventType)}</strong><small>${esc(item.description)} · ${esc(item.severity)}</small></span></span></label>`).join(''):emptyState('No event types','The notification event contract is unavailable.');
}
function renderNotificationSelectors(){
  const orgDest=$('#notification-destination-organization'),orgRoute=$('#notification-route-organization');
  setOptions(orgDest,state.organizations,item=>item.id,item=>item.displayName||item.name,'Create an organization first');
  setOptions(orgRoute,state.organizations,item=>item.id,item=>item.displayName||item.name,'Create an organization first');
  const orgId=orgRoute.value;
  const projects=notificationOrgProjects(orgId),project=$('#notification-route-project'),previousProject=project.value;
  project.innerHTML=`<option value="">All projects in organization</option>`+projects.map(item=>`<option value="${esc(item.id)}">${esc(item.displayName||item.name)}</option>`).join('');
  if([...project.options].some(option=>option.value===previousProject))project.value=previousProject;
  const active=state.notificationDestinations.filter(item=>item.organizationId===orgId&&item.state==='ACTIVE');
  const destinationSelect=$('#notification-route-destinations'),selected=new Set([...destinationSelect.selectedOptions].map(option=>option.value));
  destinationSelect.innerHTML=active.length?active.map(item=>`<option value="${esc(item.id)}"${selected.has(item.id)?' selected':''}>${esc(item.name)} · ${esc(item.kind)}</option>`).join(''):'<option value="" disabled>No active destinations</option>';
  destinationSelect.disabled=!active.length;
  renderNotificationEventTypes();
}
function renderNotificationResources(){
  const orgById=new Map(state.organizations.map(item=>[item.id,item]));
  const projectById=new Map(state.projects.map(item=>[item.id,item]));
  const destinationById=new Map(state.notificationDestinations.map(item=>[item.id,item]));
  const routeById=new Map(state.notificationRoutes.map(item=>[item.id,item]));
  const eventById=new Map(state.notificationEvents.map(item=>[item.id,item]));
  const dead=state.notificationDeliveries.filter(item=>item.state==='DEAD_LETTER').length;
  const retrying=state.notificationDeliveries.filter(item=>['PENDING','DELIVERING','RETRY_WAIT'].includes(item.state)).length;
  $('#notification-summary').innerHTML=[['Active destinations',state.notificationDestinations.filter(item=>item.state==='ACTIVE').length],['Enabled routes',state.notificationRoutes.filter(item=>item.enabled).length],['Dead letters',dead],['Pending / retrying',retrying]].map(([label,value])=>`<div class="metric"><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`).join('');
  const destinationRows=latest(state.notificationDestinations).map(item=>tableRow([
    tableCell(`<span class="cell-title">${esc(item.name)}</span><span class="cell-meta">${esc(orgById.get(item.organizationId)?.displayName||item.organizationId)}</span>`),
    tableCell(`${badge(item.kind)} ${badge(item.state)}`,'status-cell'),
    tableCell(`<span class="technical">${esc(item.endpoint||'Local console')}</span>`),
    tableCell(`${esc(item.timeoutSeconds||10)}s`,'numeric'),
    tableCell(`<div class="row-actions"><button type="button" class="secondary small-button" data-notification-destination-action="inspect" data-id="${esc(item.id)}">Inspect</button><button type="button" class="secondary small-button" data-notification-destination-action="edit" data-id="${esc(item.id)}">Edit</button>${item.state==='ACTIVE'?`<button type="button" class="danger small-button" data-notification-destination-action="disable" data-id="${esc(item.id)}">Disable</button>`:''}</div>`,'actions-cell')
  ]));
  $('#notification-destination-grid').innerHTML=dataTable('Notification destinations',[{label:'Destination'},{label:'Kind / state'},{label:'Endpoint'},{label:'Timeout',className:'numeric'},{label:'Actions'}],destinationRows,'No destinations','Create a console or webhook destination.',{source:'notification destinations'});
  const routeRows=latest(state.notificationRoutes).map(item=>tableRow([
    tableCell(`<span class="cell-title">${esc(item.name)}</span><span class="cell-meta">${esc(orgById.get(item.organizationId)?.displayName||item.organizationId)}${item.projectId?` · ${esc(projectById.get(item.projectId)?.displayName||item.projectId)}`:' · all projects'}</span>`),
    tableCell(`${badge(item.enabled?'ACTIVE':'DISABLED')} ${badge(item.minimumSeverity)}`,'status-cell'),
    tableCell(`<span class="technical">${esc((item.eventPatterns||[]).join(', ')||'—')}</span>`),
    tableCell(`${esc((item.destinationIds||[]).length)}`,'numeric'),
    tableCell(`<div class="row-actions"><button type="button" class="secondary small-button" data-notification-route-action="inspect" data-id="${esc(item.id)}">Inspect</button><button type="button" class="secondary small-button" data-notification-route-action="edit" data-id="${esc(item.id)}">Edit</button><button type="button" class="secondary small-button" data-notification-route-action="toggle" data-id="${esc(item.id)}">${item.enabled?'Disable':'Enable'}</button></div>`,'actions-cell')
  ]));
  $('#notification-route-grid').innerHTML=dataTable('Notification routing rules',[{label:'Rule / scope'},{label:'State / severity'},{label:'Event patterns'},{label:'Destinations',className:'numeric'},{label:'Actions'}],routeRows,'No routing rules','Create a rule after at least one destination exists.',{source:'notification routes'});
  const eventRows=latest(state.notificationEvents).map(item=>tableRow([
    tableCell(`<button type="button" class="table-link" data-notification-event-id="${esc(item.id)}"><span class="cell-title">${esc(item.title||item.eventType)}</span><span class="cell-meta technical">${esc(item.eventType)}</span></button>`),
    tableCell(badge(item.severity),'status-cell'),
    tableCell(`<span class="cell-meta">${esc(item.summary||'—')}</span>`),
    tableCell(formatDate(item.occurredAt),'timestamp',item.occurredAt||'')
  ]));
  $('#notification-event-grid').innerHTML=dataTable('Notification event history',[{label:'Event'},{label:'Severity'},{label:'Summary'},{label:'Occurred',className:'timestamp'}],eventRows,'No notification events','Actionable runtime events will appear after a matching condition occurs.',{source:'notification events'});
  const deliveryRows=latest(state.notificationDeliveries).map(item=>{const ev=eventById.get(item.eventId),dest=destinationById.get(item.destinationId),route=routeById.get(item.routeId);return tableRow([
    tableCell(`<button type="button" class="table-link" data-notification-delivery-id="${esc(item.id)}"><span class="cell-title technical">${esc(ev?.eventType||item.eventId)}</span><span class="cell-meta">${esc(route?.name||item.routeId)} → ${esc(dest?.name||item.destinationId)}</span></button>`),
    tableCell(badge(item.state),'status-cell'),
    tableCell(`${esc(item.attempt)} / ${esc(item.maxAttempts)}`,'numeric'),
    tableCell(formatDate(item.updatedAt),'timestamp',item.updatedAt||'')
  ]);});
  $('#notification-delivery-grid').innerHTML=dataTable('Notification delivery history',[{label:'Event / route'},{label:'State'},{label:'Attempt',className:'numeric'},{label:'Updated',className:'timestamp'}],deliveryRows,'No deliveries','Matching events create durable delivery records here.',{source:'notification deliveries'});
}
async function loadNotifications(){
  try{
    const [organizations,projects,eventTypes,destinations,routes,events,deliveries]=await Promise.all([softApi('/api/v1/organizations',[],'organizations'),softApi('/api/v1/projects',[],'projects'),softApi('/api/v1/notification-event-types',[],'notification event types'),softApi('/api/v1/notification-destinations',[],'notification destinations'),softApi('/api/v1/notification-routes',[],'notification routes'),softApi('/api/v1/notification-events?limit=100',[],'notification events'),softApi('/api/v1/notification-deliveries?limit=100',[],'notification deliveries')]);
    Object.assign(state,{organizations,projects,notificationEventTypes:eventTypes,notificationDestinations:destinations,notificationRoutes:routes,notificationEvents:events,notificationDeliveries:deliveries});
    renderNotificationSelectors();renderNotificationResources();
  }catch(error){for(const id of ['notification-destination-grid','notification-route-grid','notification-event-grid','notification-delivery-grid'])$( `#${id}` ).innerHTML=errorState(error.message);}
}
function resetNotificationDestinationForm(){
  const form=$('#notification-destination-form');form.reset();markFormClean(form);delete form.dataset.editId;delete form.dataset.revision;$('#notification-destination-organization').disabled=false;$('#notification-destination-timeout').value='10';$('#notification-webhook-fields').hidden=true;$('#notification-destination-endpoint').required=false;$('#notification-destination-submit').textContent='Create destination';$('#notification-destination-cancel-edit').hidden=true;renderNotificationSelectors();
}
function editNotificationDestination(item){
  const form=$('#notification-destination-form');form.dataset.editId=item.id;form.dataset.revision=item.revision;$('#notification-destination-organization').value=item.organizationId;$('#notification-destination-organization').disabled=true;$('#notification-destination-name').value=item.name;$('#notification-destination-kind').value=item.kind;const webhook=item.kind==='WEBHOOK';$('#notification-webhook-fields').hidden=!webhook;$('#notification-destination-endpoint').required=webhook;$('#notification-destination-endpoint').value=item.endpoint||'';$('#notification-destination-auth-env').value=item.authorizationEnv||'';$('#notification-destination-hmac-env').value=item.hmacSecretEnv||'';$('#notification-destination-timeout').value=item.timeoutSeconds||10;$('#notification-destination-allow-http').checked=item.allowHttp===true;$('#notification-destination-submit').textContent='Save destination';$('#notification-destination-cancel-edit').hidden=false;markFormClean(form);form.scrollIntoView({behavior:'smooth',block:'center'});
}
function resetNotificationRouteForm(){
  const form=$('#notification-route-form');form.reset();markFormClean(form);delete form.dataset.editId;delete form.dataset.revision;delete form.dataset.enabled;$('#notification-route-organization').disabled=false;$('#notification-route-submit').textContent='Create routing rule';$('#notification-route-cancel-edit').hidden=true;renderNotificationSelectors();
}
function editNotificationRoute(item){
  const form=$('#notification-route-form');form.dataset.editId=item.id;form.dataset.revision=item.revision;form.dataset.enabled=String(item.enabled);$('#notification-route-organization').value=item.organizationId;$('#notification-route-organization').disabled=true;renderNotificationSelectors();$('#notification-route-project').value=item.projectId||'';$('#notification-route-name').value=item.name;$('#notification-route-severity').value=item.minimumSeverity;const patterns=new Set(item.eventPatterns||[]);$$('#notification-event-type-list input').forEach(input=>{input.checked=patterns.has(input.value);});const destinations=new Set(item.destinationIds||[]);[...$('#notification-route-destinations').options].forEach(option=>{option.selected=destinations.has(option.value);});$('#notification-route-submit').textContent='Save routing rule';$('#notification-route-cancel-edit').hidden=false;markFormClean(form);form.scrollIntoView({behavior:'smooth',block:'center'});
}
$('#notification-destination-kind').onchange=()=>{const webhook=$('#notification-destination-kind').value==='WEBHOOK';$('#notification-webhook-fields').hidden=!webhook;$('#notification-destination-endpoint').required=webhook;};
$('#notification-route-organization').onchange=renderNotificationSelectors;
$('#notification-destination-cancel-edit').onclick=async()=>{const form=$('#notification-destination-form');if(!await confirmDiscardDirty(form,'Discard destination changes?','Cancel editing and discard unsaved notification destination changes?'))return;resetNotificationDestinationForm();};
$('#notification-route-cancel-edit').onclick=async()=>{const form=$('#notification-route-form');if(!await confirmDiscardDirty(form,'Discard routing changes?','Cancel editing and discard unsaved notification routing changes?'))return;resetNotificationRouteForm();};
$('#notification-destination-form').onsubmit=async event=>{
  event.preventDefault();const form=event.currentTarget;if(!form.reportValidity())return;const kind=$('#notification-destination-kind').value;const editing=form.dataset.editId;
  const body={organizationId:editing?(state.notificationDestinations.find(item=>item.id===editing)?.organizationId||$('#notification-destination-organization').value):$('#notification-destination-organization').value,name:$('#notification-destination-name').value.trim(),kind,endpoint:kind==='WEBHOOK'?$('#notification-destination-endpoint').value.trim():'',authorizationEnv:kind==='WEBHOOK'?$('#notification-destination-auth-env').value.trim():'',hmacSecretEnv:kind==='WEBHOOK'?$('#notification-destination-hmac-env').value.trim():'',allowHttp:kind==='WEBHOOK'&&$('#notification-destination-allow-http').checked,timeoutSeconds:Number($('#notification-destination-timeout').value||10)};
  try{if(editing)await api(`/api/v1/notification-destinations/${editing}`,{method:'PUT',headers:{'If-Match':`"${form.dataset.revision}"`},body});else await api('/api/v1/notification-destinations',{method:'POST',body});toast(editing?'Notification destination updated.':'Notification destination created.');resetNotificationDestinationForm();await loadNotifications();}catch(error){toast(error.message,'error');}
};
$('#notification-route-form').onsubmit=async event=>{
  event.preventDefault();const form=event.currentTarget;if(!form.reportValidity())return;const eventPatterns=$$('#notification-event-type-list input:checked').map(input=>input.value),destinationIds=[...$('#notification-route-destinations').selectedOptions].map(option=>option.value).filter(Boolean);if(!eventPatterns.length){toast('Select at least one event type.','error');return;}if(!destinationIds.length){toast('Select at least one active destination.','error');return;}const editing=form.dataset.editId;
  const body={organizationId:editing?(state.notificationRoutes.find(item=>item.id===editing)?.organizationId||$('#notification-route-organization').value):$('#notification-route-organization').value,projectId:$('#notification-route-project').value||'',name:$('#notification-route-name').value.trim(),enabled:editing?form.dataset.enabled==='true':true,eventPatterns,minimumSeverity:$('#notification-route-severity').value,destinationIds};
  try{if(editing)await api(`/api/v1/notification-routes/${editing}`,{method:'PUT',headers:{'If-Match':`"${form.dataset.revision}"`},body});else await api('/api/v1/notification-routes',{method:'POST',body});toast(editing?'Notification routing rule updated.':'Notification routing rule created.');resetNotificationRouteForm();await loadNotifications();}catch(error){toast(error.message,'error');}
};
$('#notification-destination-grid').onclick=async event=>{const button=event.target.closest('[data-notification-destination-action]');if(!button)return;const item=state.notificationDestinations.find(v=>v.id===button.dataset.id);if(!item)return;if(button.dataset.notificationDestinationAction==='inspect'){showDetails('Notification destination',`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(item.id)}</dd><dt>Kind / state</dt><dd>${badge(item.kind)} ${badge(item.state)}</dd><dt>Endpoint</dt><dd class="technical">${esc(item.endpoint||'Local console')}</dd><dt>Authorization env</dt><dd class="technical">${esc(item.authorizationEnv||'—')}</dd><dt>HMAC env</dt><dd class="technical">${esc(item.hmacSecretEnv||'—')}</dd><dt>Allow HTTP</dt><dd>${item.allowHttp?'yes':'no'}</dd><dt>Revision</dt><dd>${esc(item.revision)}</dd></dl>`);return;}if(button.dataset.notificationDestinationAction==='edit'){const form=$('#notification-destination-form');if(form.dataset.editId===item.id&&dirtyWithin(form)){form.scrollIntoView({behavior:'smooth',block:'center'});return;}if(!await confirmDiscardDirty(form,'Replace unsaved destination changes?','Open this destination and discard the unsaved values currently in the destination editor?'))return;editNotificationDestination(item);return;}if(button.dataset.notificationDestinationAction==='disable'){if(!await confirmAction('Disable notification destination','Disable this destination? Existing history remains, but new matching deliveries will no longer target it.',true))return;try{await api(`/api/v1/notification-destinations/${item.id}/disable`,{method:'POST',headers:{'If-Match':`"${item.revision}"`,'X-Confirm-Disable':'disable-notification-destination'},body:{}});toast('Notification destination disabled.');await loadNotifications();}catch(error){toast(error.message,'error');}}};
$('#notification-route-grid').onclick=async event=>{const button=event.target.closest('[data-notification-route-action]');if(!button)return;const item=state.notificationRoutes.find(v=>v.id===button.dataset.id);if(!item)return;if(button.dataset.notificationRouteAction==='inspect'){showDetails('Notification route',`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(item.id)}</dd><dt>Enabled</dt><dd>${esc(item.enabled)}</dd><dt>Minimum severity</dt><dd>${badge(item.minimumSeverity)}</dd><dt>Event patterns</dt><dd class="technical">${esc((item.eventPatterns||[]).join(', '))}</dd><dt>Destinations</dt><dd class="technical">${esc((item.destinationIds||[]).join(', '))}</dd><dt>Revision</dt><dd>${esc(item.revision)}</dd></dl>`);return;}if(button.dataset.notificationRouteAction==='edit'){const form=$('#notification-route-form');if(form.dataset.editId===item.id&&dirtyWithin(form)){form.scrollIntoView({behavior:'smooth',block:'center'});return;}if(!await confirmDiscardDirty(form,'Replace unsaved routing changes?','Open this routing rule and discard the unsaved values currently in the routing editor?'))return;editNotificationRoute(item);return;}if(button.dataset.notificationRouteAction==='toggle'){try{await api(`/api/v1/notification-routes/${item.id}`,{method:'PUT',headers:{'If-Match':`"${item.revision}"`},body:{organizationId:item.organizationId,projectId:item.projectId||'',name:item.name,enabled:!item.enabled,eventPatterns:item.eventPatterns,minimumSeverity:item.minimumSeverity,destinationIds:item.destinationIds}});toast(item.enabled?'Routing rule disabled.':'Routing rule enabled.');await loadNotifications();}catch(error){toast(error.message,'error');}}};
$('#notification-event-grid').onclick=event=>{const button=event.target.closest('[data-notification-event-id]');if(!button)return;const item=state.notificationEvents.find(v=>v.id===button.dataset.notificationEventId);if(!item)return;showDetails(item.title||item.eventType,`<dl class="key-value"><dt>Event type</dt><dd class="technical">${esc(item.eventType)}</dd><dt>Severity</dt><dd>${badge(item.severity)}</dd><dt>Source event</dt><dd class="technical">${esc(item.sourceEventId)}</dd><dt>Aggregate</dt><dd class="technical">${esc(item.aggregateType)} / ${esc(item.aggregateId)}</dd><dt>Occurred</dt><dd>${formatDate(item.occurredAt)}</dd><dt>Summary</dt><dd>${esc(item.summary||'—')}</dd></dl>`);};
$('#notification-delivery-grid').onclick=async event=>{const button=event.target.closest('[data-notification-delivery-id]');if(!button)return;try{const view=await api(`/api/v1/notification-deliveries/${button.dataset.notificationDeliveryId}`),item=view.delivery,sourceEvent=view.event||state.notificationEvents.find(v=>v.id===item.eventId)||null,attempts=view.attempts||[];const retryScope=sourceEvent?.projectId?` data-project-scope="${esc(sourceEvent.projectId)}"`:sourceEvent?.organizationId?` data-organization-scope="${esc(sourceEvent.organizationId)}"`:' data-project-scope="__permission-scope-unavailable__"';const retry=item.state==='DEAD_LETTER'?`<div class="detail-section"><button type="button" data-notification-retry-dead-letter${retryScope} class="primary">Requeue dead letter</button></div>`:'';showDetails('Notification delivery',`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(item.id)}</dd><dt>State</dt><dd>${badge(item.state)}</dd><dt>Attempt</dt><dd>${esc(item.attempt)} / ${esc(item.maxAttempts)}</dd><dt>Last HTTP status</dt><dd>${esc(item.lastStatusCode||'—')}</dd><dt>Last error</dt><dd>${esc(item.lastError||'—')}</dd><dt>Next attempt</dt><dd>${formatDate(item.nextAttemptAt)}</dd></dl><div class="detail-section"><h3>Immutable attempts</h3><div class="timeline">${attempts.length?attempts.map(attempt=>`<div class="timeline-step ${attempt.success?'success':attempt.retryable?'':'failed'}"><span class="timeline-dot">${attempt.success?'✓':'!'}</span><div><h4>Attempt ${esc(attempt.attempt)}</h4><p>${attempt.success?'SUCCEEDED':attempt.retryable?'RETRYABLE':'FAILED'} · HTTP ${esc(attempt.statusCode||'—')} · ${esc(attempt.durationMillis||0)} ms${attempt.error?` · ${esc(attempt.error)}`:''}</p><small class="technical">${esc(attempt.responseDigest||'—')}</small></div></div>`).join(''):'<p>No attempts recorded.</p>'}</div></div>${retry}`);if(item.state==='DEAD_LETTER')setTimeout(()=>{const retryButton=document.querySelector('[data-notification-retry-dead-letter]');if(retryButton)retryButton.onclick=async()=>{if(!await confirmAction('Requeue dead letter','Retry this durable delivery after the destination problem has been corrected?'))return;try{await api(`/api/v1/notification-deliveries/${item.id}/retry`,{method:'POST',headers:{'If-Match':`"${item.revision}"`},body:{}});closeDetails();toast('Dead letter requeued.');await loadNotifications();}catch(error){toast(error.message,'error');}};},0);}catch(error){toast(error.message,'error');}};

async function loadServices(){
  const services=await softApi('/api/v1/system-services',[],'system services');state.services=services;
  $('#service-grid').innerHTML=services.length?services.map(service=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(service.name)}</h3><div class="resource-meta">${badge(service.healthy?'HEALTHY':service.configured?'UNAVAILABLE':'NOT CONFIGURED')}${badge(service.provider||'managed')}</div></div></div><p>${service.endpoint?technical(service.endpoint):'Managed endpoint is not configured.'}</p><div class="resource-details">${detailRow('Version',service.version||'Not reported',true)}${detailRow('Configured',service.configured?'yes':'no')}${detailRow('Healthy',service.healthy?'yes':'no')}${service.credentialId?detailRow('Credential ID',service.credentialId,true):''}${service.credentialRef?detailRow('Secret reference',service.credentialRef,true):''}</div>${service.error?`<div class="warning-banner">${esc(service.error)}</div>`:''}</article>`).join(''):emptyState('No system services','System service integration records are unavailable.');
  try{
    const authority=await api('/api/v1/git-authority');state.gitAuthority=authority;state.gitProviders=authority.providers||[];state.gitCredentials=authority.credentials||[];
    const provider=state.gitProviders.find(v=>v.default&&v.state==='ACTIVE')||state.gitProviders.find(v=>v.state==='ACTIVE')||state.gitProviders[0],credential=provider?state.gitCredentials.find(v=>v.id===provider.credentialId):null;
    $('#git-authority-summary').innerHTML=provider&&credential?`<div class="resource-details">${detailRow('Method',authority.method,true)}${detailRow('Provider',provider.name)}${detailRow('Endpoint',provider.baseUrl,true)}${detailRow('Provider state',provider.state)}${detailRow('Credential',credential.id,true)}${detailRow('Credential state',credential.state)}${detailRow('Username',credential.username,true)}${detailRow('Secret reference',credential.secretRef,true)}${detailRow('Raw secret persisted',authority.secretMaterialPersisted?'YES':'no')}</div>`:emptyState('Git authority not configured','Create a credential reference and connect Forgejo below.');
    const activeCredentials=state.gitCredentials.filter(item=>item.state==='ACTIVE');
    $('#git-provider-create-credential').innerHTML=activeCredentials.length?activeCredentials.map(item=>`<option value="${esc(item.id)}">${esc(item.name)} · ${esc(item.username)} · ${esc(item.secretRef)}</option>`).join(''):'<option value="" disabled selected>Create an active credential first</option>';
    setIntrinsicDisabled($('#git-provider-create-credential'), !activeCredentials.length);
    $('#git-provider-grid').innerHTML=state.gitProviders.length?state.gitProviders.map(item=>{const bound=state.gitCredentials.find(credential=>credential.id===item.credentialId);const options=activeCredentials.map(credential=>`<option value="${esc(credential.id)}"${credential.id===item.credentialId?' selected':''}>${esc(credential.name)} · ${esc(credential.username)}</option>`).join('');return `<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.name)}</h3><div class="resource-meta">${badge(item.kind)}${badge(item.state)}${item.default?badge('DEFAULT'):''}</div></div></div><p class="technical">${esc(item.baseUrl)}</p><div class="resource-details">${detailRow('Credential',bound?.name||item.credentialId)}${detailRow('Credential state',bound?.state||'missing')}${detailRow('Secret reference',bound?.secretRef||'—',true)}${detailRow('Revision',item.revision)}</div><div class="form-stack"><label><span>Rebind credential</span><select data-git-provider-credential="${esc(item.id)}" ${activeCredentials.length?'':'disabled'}>${options||'<option disabled>No active credentials</option>'}</select></label><button type="button" class="secondary small-button" data-git-provider-action="rebind" data-id="${esc(item.id)}" ${canAdminister()&&activeCredentials.length?'':'disabled title="platform-admin required"'}>Rebind credential</button></div></article>`;}).join(''):emptyState('No Git providers','Create a credential reference, then connect the internal Forgejo provider.');
    $('#git-credential-username').value=credential?.username||'';$('#git-credential-rotate-form').dataset.credentialId=credential?.id||'';$('#git-credential-rotate-form').dataset.revision=credential?.revision||'';setIntrinsicDisabled($('#git-credential-revoke'), !canAdminister()||!credential||credential.state!=='ACTIVE');
    for(const form of [$('#git-credential-create-form'),$('#git-provider-create-form')]){const submit=form.querySelector('button[type="submit"]');setIntrinsicDisabled(submit, !canAdminister());submit.title=canAdminister()?'':'platform-admin required';}
  }catch(error){state.gitAuthority=null;state.gitProviders=[];state.gitCredentials=[];$('#git-authority-summary').innerHTML=`<div class="inline-note">Git credential authority requires platform-admin. ${esc(error.message)}</div>`;$('#git-provider-grid').innerHTML='';$('#git-provider-create-credential').innerHTML='<option value="" disabled selected>platform-admin required</option>';setIntrinsicDisabled($('#git-provider-create-credential'), true);setIntrinsicDisabled($('#git-credential-revoke'), true);}
  await loadGitDeliveryAuthority();
}

$('#git-credential-create-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;if(!canAdminister()){toast('Git credential authority requires platform-admin.','error');return;}try{await api('/api/v1/git-credentials',{method:'POST',body:{name:$('#git-credential-create-name').value.trim(),username:$('#git-credential-create-username').value.trim(),secretRef:$('#git-credential-create-secret-ref').value.trim()}});event.currentTarget.reset();toast('Git credential reference created.');await loadServices();}catch(error){toast(error.message,'error');}};
$('#git-provider-create-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;if(!canAdminister()){toast('Git provider authority requires platform-admin.','error');return;}try{await api('/api/v1/git-providers',{method:'POST',body:{name:$('#git-provider-create-name').value.trim(),kind:'FORGEJO',baseUrl:$('#git-provider-create-base-url').value.trim(),credentialId:$('#git-provider-create-credential').value,default:$('#git-provider-create-default').checked}});event.currentTarget.reset();$('#git-provider-create-default').checked=true;toast('Forgejo provider connected.');await loadServices();}catch(error){toast(error.message,'error');}};
$('#git-provider-grid').onclick=async event=>{const button=event.target.closest('[data-git-provider-action]');if(!button)return;const item=state.gitProviders.find(row=>row.id===button.dataset.id);if(!item)return;if(button.dataset.gitProviderAction==='rebind'){const select=$(`[data-git-provider-credential="${item.id}"]`);const credentialId=select?.value;if(!credentialId||credentialId===item.credentialId){toast(credentialId?'Provider already uses this credential.':'Select an active credential.','error');return;}try{await api(`/api/v1/git-providers/${item.id}/credential`,{method:'PUT',headers:{'If-Match':`"${item.revision}"`},body:{credentialId}});toast('Git provider credential binding updated.');await loadServices();}catch(error){toast(error.message,'error');}}};

async function loadGitDeliveryAuthority(){
  try{
    const [pullRequests,revisions]=await Promise.all([softApi('/api/v1/system-services/git/pull-requests',[],'Git pull requests'),softApi('/api/v1/system-services/git/revisions',[],'Git revisions')]);
    state.gitPullRequests=pullRequests||[];state.managedGitRevisions=revisions||[];const open=state.gitPullRequests.filter(v=>v.state==='OPEN').length,approved=state.gitPullRequests.filter(v=>v.state==='APPROVED').length,lkg=state.managedGitRevisions.filter(v=>v.lastKnownGood);
    $('#git-delivery-summary').innerHTML=[['Delivery authority','PR + LKG v1'],['Open PRs',open],['Approved PRs',approved],['Last-known-good',lkg.length]].map(([label,value])=>`<article class="metric-card"><span>${esc(label)}</span><strong>${esc(value)}</strong></article>`).join('');
    $('#git-pull-request-grid').innerHTML=state.gitPullRequests.length?state.gitPullRequests.slice().reverse().map(pr=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">PR</span><div><strong>${esc(pr.revisionId)}</strong><small>${badge(pr.state)} #${esc(pr.externalNumber)} · ${technical(pr.headBranch)} → ${technical(pr.baseBranch)}</small><small>${technical(pr.digest)}</small></div></div><div class="button-row">${pr.state==='OPEN'?`<button class="secondary small-button" data-git-pr-action="approve" data-pr-id="${esc(pr.id)}" data-revision="${esc(pr.revision)}">Approve</button>`:''}${pr.state==='APPROVED'?`<button class="primary small-button" data-git-pr-action="merge" data-pr-id="${esc(pr.id)}" data-revision="${esc(pr.revision)}">Merge</button>`:''}${pr.externalUrl?`<a class="secondary small-button" href="${esc(pr.externalUrl)}" target="_blank" rel="noopener">Open Git</a>`:''}</div></div>`).join(''):emptyState('No pull requests','Publish a signed revision using Pull request delivery mode.');
    $('#git-lkg-grid').innerHTML=lkg.length?lkg.slice().reverse().map(v=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">✓</span><div><strong>${esc(v.revisionId)}</strong><small>${badge('LAST KNOWN GOOD')} ${technical(v.organization+'/'+v.repository+'@'+v.branch)}</small><small>${technical(v.commitSha)} · ${technical(v.digest)}</small></div></div><button class="danger small-button" data-git-lkg-rollback="${esc(v.id)}" data-lkg-revision="${v.revision}" data-lkg-commit="${esc(v.commitSha)}" data-organization="${esc(v.organization)}" data-repository="${esc(v.repository)}" data-branch="${esc(v.branch)}">Rollback to LKG</button></div>`).join(''):emptyState('No last-known-good revision','A managed revision becomes LKG only after healthy sync observation with a matching digest.');
  }catch(error){$('#git-delivery-summary').innerHTML='';$('#git-pull-request-grid').innerHTML=errorState(error.message);$('#git-lkg-grid').innerHTML='';}
}

$('#git-credential-rotate-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const id=event.currentTarget.dataset.credentialId,revision=event.currentTarget.dataset.revision;if(!id||!revision){toast('No active Git credential is available to rotate.','error');return;}try{await api(`/api/v1/git-credentials/${id}/rotate`,{method:'POST',headers:{'If-Match':`"${revision}"`},body:{username:$('#git-credential-username').value.trim(),secretRef:$('#git-credential-secret-ref').value.trim()}});$('#git-credential-secret-ref').value='';toast('Git credential reference rotated and provider binding updated.');await loadServices();}catch(error){toast(error.message,'error');}};
$('#git-credential-revoke').onclick=async()=>{const form=$('#git-credential-rotate-form'),id=form.dataset.credentialId,revision=form.dataset.revision;if(!id||!revision)return;if(!await confirmAction('Revoke Git credential','Revoke the active Git credential reference? Git write/read operations will fail closed until the provider is rebound or a new credential is rotated in.',true))return;try{await api(`/api/v1/git-credentials/${id}/revoke`,{method:'POST',headers:{'If-Match':`"${revision}"`},body:{}});toast('Git credential revoked.');await loadServices();}catch(error){toast(error.message,'error');}};

function renderGitFiles(){
  const entries=Object.entries(state.gitRevisionFiles);
  $('#git-file-list').innerHTML=entries.length?entries.map(([path,content])=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">F</span><div><strong class="technical">${esc(path)}</strong><small>${esc(content.length)} characters</small></div></div><button type="button" class="secondary small-button" data-remove-git-file="${esc(path)}">Remove</button></div>`).join(''):emptyState('No files added','Add at least one explicit repository file before publishing.');
}
$('#git-add-file').onclick=()=>{
  const path=$('#git-file-path').value.trim().replace(/^\/+/,''),content=$('#git-file-content').value;
  if(!path||!content){toast('File path and content are required.','error');return;}
  if(path.includes('..')){toast('Parent directory traversal is not allowed.','error');return;}
  state.gitRevisionFiles[path]=content;$('#git-file-path').value='';$('#git-file-content').value='';renderGitFiles();
};
$('#git-file-list').onclick=event=>{const button=event.target.closest('[data-remove-git-file]');if(!button)return;delete state.gitRevisionFiles[button.dataset.removeGitFile];renderGitFiles();};
$('#git-repository-form').onsubmit=async event=>{
  event.preventDefault();if(!event.currentTarget.reportValidity())return;
  try{const result=await api('/api/v1/system-services/git/repositories',{method:'POST',body:{organization:$('#git-repository-organization').value.trim(),name:$('#git-repository-name').value.trim(),description:$('#git-repository-description').value.trim(),private:$('#git-repository-private').checked}});$('#git-repository-result').innerHTML=`<div class="success-banner"><strong>${result.created?'Repository created':'Repository already existed'}</strong><div class="resource-details">${detailRow('Organization',result.organization,true)}${detailRow('Repository',result.name,true)}${detailRow('Seeded',result.seeded?'yes':'no')}${result.htmlUrl?detailRow('URL',result.htmlUrl,true):''}</div></div>`;$('#git-revision-organization').value=result.organization;$('#git-revision-repository').value=result.name;toast('Repository contract completed.');await loadServices();}catch(error){$('#git-repository-result').innerHTML=errorState(error.message);toast(error.message,'error');}
};
$('#git-revision-form').onsubmit=async event=>{
  event.preventDefault();if(!event.currentTarget.reportValidity())return;
  if(!Object.keys(state.gitRevisionFiles).length){toast('Add at least one desired-state file.','error');return;}
  try{const result=await api('/api/v1/system-services/git/revisions',{method:'POST',body:{organization:$('#git-revision-organization').value.trim(),repository:$('#git-revision-repository').value.trim(),revisionId:$('#git-revision-id').value.trim(),digest:$('#git-revision-digest').value.trim(),deliveryMode:$('#git-revision-delivery-mode').value,files:state.gitRevisionFiles}});const pr=result.pullRequest;$('#git-revision-result').innerHTML=pr?`<div class="success-banner"><strong>Pull request staged for review</strong><div class="resource-details">${detailRow('Revision',pr.revisionId,true)}${detailRow('Digest',pr.digest,true)}${detailRow('Pull request','#'+pr.externalNumber)}${detailRow('Head branch',pr.headBranch,true)}${detailRow('State',pr.state)}${detailRow('Changed files',result.changedFiles)}</div></div>`:`<div class="success-banner"><strong>Revision published</strong><div class="resource-details">${detailRow('Revision',result.revisionId,true)}${detailRow('Digest',result.digest,true)}${detailRow('Commit SHA',result.commitSha,true)}${detailRow('Changed files',result.changedFiles)}</div></div>`;state.gitRevisionFiles={};renderGitFiles();toast(pr?'Pull request created. Review and approve it before merge.':'Desired-state revision published.');await loadGitDeliveryAuthority();}catch(error){$('#git-revision-result').innerHTML=errorState(error.message);toast(error.message,'error');}
};
$('#git-pull-request-grid').onclick=async event=>{const button=event.target.closest('[data-git-pr-action]');if(!button)return;const action=button.dataset.gitPrAction,id=button.dataset.prId,revision=button.dataset.revision;if(action==='merge'&&!await confirmAction('Merge signed pull request','Merge this approved signed revision into the managed desired-state branch?',true))return;try{await api(`/api/v1/system-services/git/pull-requests/${id}/${action}`,{method:'POST',headers:{'If-Match':`"${revision}"`},body:{}});toast(action==='approve'?'Pull request approved.':'Pull request merged and recorded as managed desired state.');await loadGitDeliveryAuthority();}catch(error){toast(error.message,'error');}};
$('#git-lkg-grid').onclick=async event=>{const button=event.target.closest('[data-git-lkg-rollback]');if(!button)return;if(!await confirmAction('Rollback Git desired state',`Restore ${button.dataset.organization}/${button.dataset.repository}@${button.dataset.branch} to its last-known-good signed revision? A fresh sync observation is required afterward.`,true))return;try{const lkgRevision=Number(button.dataset.lkgRevision);const headers={'X-Confirm-Rollback':`rollback:${button.dataset.gitLkgRollback}:${lkgRevision}`};const result=await api('/api/v1/system-services/git/last-known-good/rollback',{method:'POST',headers,body:{organization:button.dataset.organization,repository:button.dataset.repository,branch:button.dataset.branch,lkgId:button.dataset.gitLkgRollback,lkgRevision,commitSha:button.dataset.lkgCommit}});toast(`Rollback commit ${result.rollbackRevision.commitSha.slice(0,12)} created. Awaiting sync observation.`);await loadGitDeliveryAuthority();}catch(error){toast(error.message,'error');}};
renderGitFiles();

const defaultBlueprintOwnershipRules=[
  {path:'/spec/delivery/repository',policy:'PROVIDER_ONLY'},
  {path:'/spec/delivery/ociRegistry',policy:'PROVIDER_ONLY'},
  {path:'/spec/description',policy:'PROVIDER_THEN_ENVIRONMENT'},
  {path:'/spec/certification/requiredLevel',policy:'ENVIRONMENT_ONLY'},
  {path:'/spec/certification/evidenceRetentionDays',policy:'ENVIRONMENT_ONLY'}
];
function ownershipRulesText(rules){return (rules||[]).map(rule=>`${rule.path} | ${rule.policy}`).join('\n');}
function ownershipRulesFromEditor(){
  const lines=$('#blueprint-field-ownership').value.split(/\r?\n/).map(v=>v.trim()).filter(Boolean),out=[];
  for(const line of lines){const parts=line.split('|').map(v=>v.trim());if(parts.length!==2||!parts[0].startsWith('/spec/'))throw new Error(`Invalid ownership rule: ${line}`);out.push({path:parts[0],policy:parts[1]});}
  return out;
}
function parseOverlayChanges(){
  const lines=$('#blueprint-overlay-changes').value.split(/\r?\n/).map(v=>v.trim()).filter(Boolean),changes=[];
  for(const line of lines){const idx=line.indexOf('=');if(idx<=0)throw new Error(`Invalid overlay change: ${line}`);const path=line.slice(0,idx).trim(),raw=line.slice(idx+1).trim();let value;try{value=JSON.parse(raw);}catch(error){throw new Error(`Invalid JSON value for ${path}: ${error.message}`);}changes.push({path,value});}
  return changes;
}
function renderBlueprintOverlayOptions(){
  const projectId=$('#blueprint-project')?.value||'';
  const provider=$('#blueprint-provider-overlay'),environment=$('#blueprint-environment-overlay');if(!provider||!environment)return;
  const previousProvider=provider.value,previousEnvironment=environment.value;
  const matching=state.blueprintOverlays.filter(item=>item.projectId===projectId);
  provider.innerHTML=`<option value="">No provider overlay</option>${matching.filter(item=>item.scope==='PROVIDER').map(item=>`<option value="${esc(item.id)}">${esc(item.name)}@${esc(item.version)} · ${esc(item.scopeKey)}</option>`).join('')}`;
  environment.innerHTML=`<option value="">No environment overlay</option>${matching.filter(item=>item.scope==='ENVIRONMENT').map(item=>`<option value="${esc(item.id)}">${esc(item.name)}@${esc(item.version)} · ${esc(item.scopeKey)}</option>`).join('')}`;
  if(matching.some(item=>item.id===previousProvider))provider.value=previousProvider;if(matching.some(item=>item.id===previousEnvironment))environment.value=previousEnvironment;
}
function renderBlueprintOverlays(){
  const projectById=new Map(state.projects.map(item=>[item.id,item]));
  setOptions($('#blueprint-overlay-project'),state.projects,item=>item.id,item=>item.displayName||item.name,'Create a project first');
  $('#blueprint-overlay-grid').innerHTML=state.blueprintOverlays.length?latest(state.blueprintOverlays).map(item=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.name)} <span class="technical">${esc(item.version)}</span></h3><div class="resource-meta">${badge(item.scope)}${badge(item.scopeKey)}</div></div></div><p>${esc(projectById.get(item.projectId)?.displayName||item.projectId)}</p><div class="resource-details">${detailRow('Digest',shortDigest(item.digest))}${detailRow('Changes',(item.changes||[]).length)}${detailRow('Created by',item.createdBy||'—')}</div><details><summary>Immutable changes</summary><pre class="code-block technical" dir="ltr">${esc(JSON.stringify(item.changes,null,2))}</pre></details></article>`).join(''):emptyState('No overlays','Create a provider or environment overlay when a Blueprint explicitly delegates fields.');
  renderBlueprintOverlayOptions();
}
function blueprintPlanValues(){ return Array.isArray(state.tenantPlans) ? state.tenantPlans : Object.values(state.tenantPlans || {}); }
function blueprintActiveCatalog(){ return state.blueprintCatalogComponents || state.catalog; }
function blueprintDistributionProfiles(){
  const names=new Set();
  blueprintActiveCatalog().forEach(component=>(component.spec?.compatibility?.distributionProfiles||[]).forEach(name=>names.add(name)));
  return [...names].sort();
}
function captureBlueprintComponentDraft(){
  $$('#blueprint-component-list [data-blueprint-component-present]').forEach(input=>{const name=input.value;const enabled=$$('#blueprint-component-list [data-blueprint-component-enabled]').find(row=>row.value===name);const settings=$(`[data-blueprint-component-settings="${name}"]`);state.blueprintComponentDraft[name]={present:input.checked,enabled:!!enabled?.checked,settingsText:settings?.value||'{}'};});
}
function componentSelectionsFromEditor(){
  captureBlueprintComponentDraft(); const out=[];
  for(const [name,draft] of Object.entries(state.blueprintComponentDraft)){if(!draft.present)continue;let settings={};try{settings=JSON.parse(draft.settingsText||'{}');}catch(error){throw new Error(`Component ${name} settings JSON: ${error.message}`);}if(settings===null||Array.isArray(settings)||typeof settings!=='object')throw new Error(`Component ${name} settings must be a JSON object.`);const row={name,enabled:draft.enabled===true};if(Object.keys(settings).length)row.settings=settings;out.push(row);}
  return out.sort((a,b)=>a.name.localeCompare(b.name));
}
function renderBlueprintParitySummary(){const c=state.blueprintAuthoringContract;if(!c){$('#blueprint-parity-summary').textContent='Authoring contract unavailable.';return;}const present=c.fields.filter(f=>document.getElementById(f.uiControlId)).length;$('#blueprint-parity-summary').innerHTML=`<strong>${esc(c.method)}</strong> · ${present}/${c.fieldCount} API fields have visual controls · strict unknown fields ${c.strictUnknownFields?'ON':'OFF'}`;$('#blueprint-parity-badge').className=`badge ${present===c.fieldCount?'success':'warning'}`;$('#blueprint-parity-badge').textContent=present===c.fieldCount?'API PARITY':'PARITY GAP';}
function blueprintAuthoringOptions(path){const field=state.blueprintAuthoringContract?.fields?.find(item=>item.path===path);return Array.isArray(field?.options)?field.options:[];}
function renderBlueprintKubernetesOptions(){for(const [path,id] of [['spec.compatibility.kubernetes.minVersion','blueprint-k8s-min'],['spec.compatibility.kubernetes.maxVersion','blueprint-k8s-max']]){const select=$(`#${id}`);if(!select)continue;const previous=select.value,options=blueprintAuthoringOptions(path);select.innerHTML=`<option value="">Select version</option>${options.map(value=>`<option value="${esc(value)}">${esc(value)}</option>`).join('')}`;if(options.includes(previous))select.value=previous;}}
function renderBlueprintAuthoringOptions(){
  renderBlueprintKubernetesOptions();
  const project=$('#blueprint-project');
  setOptions(project,state.projects,item=>item.id,item=>`${item.displayName||item.name} · ${item.name}`,'Create a project first');
  const plans=blueprintPlanValues();
  const planSelect=$('#blueprint-tenant-plans');
  const selectedPlans=new Set([...planSelect.selectedOptions].map(option=>option.value));
  planSelect.innerHTML=plans.length?plans.map(item=>`<option value="${esc(item.name)}"${selectedPlans.has(item.name)?' selected':''}>${esc(item.name)}</option>`).join(''):'<option value="">No tenant plans</option>';
  planSelect.disabled=!plans.length;
  const distributions=blueprintDistributionProfiles();
  const selectedDistributions=new Set($$('#blueprint-distribution-list input:checked').map(input=>input.value));
  $('#blueprint-distribution-list').innerHTML=distributions.length?distributions.map(name=>`<label class="activity-item"><span class="activity-main"><input type="checkbox" data-blueprint-distribution value="${esc(name)}"${selectedDistributions.has(name)?' checked':''}><span><strong class="technical">${esc(name)}</strong><small>Supported by the shipped component catalog.</small></span></span></label>`).join(''):emptyState('No distribution profiles','The shipped catalog does not expose compatible distribution profiles.');
  captureBlueprintComponentDraft();
  const activeCatalog=blueprintActiveCatalog();
  $('#blueprint-component-list').innerHTML=activeCatalog.length?activeCatalog.map(component=>{const name=component.metadata?.name||'';const mandatory=component.spec?.mandatory===true;const draft=state.blueprintComponentDraft[name]||{};const present=mandatory||draft.present===true;const enabled=mandatory||draft.enabled===true;const settings=draft.settingsText||'{}';return `<article class="activity-item component-author-row"><div class="activity-main"><div><strong>${esc(component.spec?.displayName||name)}</strong><small><span class="technical">${esc(name)}</span> · ${esc(component.spec?.category||'component')} · release ${esc(component.spec?.release||'—')}</small><div class="form-grid two"><label class="check-row"><input type="checkbox" data-blueprint-component-present value="${esc(name)}"${present?' checked':''}${mandatory?' disabled':''}><span>Include in API document</span></label><label class="check-row"><input type="checkbox" data-blueprint-component-enabled value="${esc(name)}"${enabled?' checked':''}${mandatory?' disabled':''}><span>Enabled</span></label></div><details><summary>Component settings JSON</summary><label><span class="visually-hidden">Component settings JSON for ${esc(component.spec?.displayName||name)}</span><textarea data-blueprint-component-settings="${esc(name)}" class="technical compact" dir="ltr">${esc(settings)}</textarea></label></details></div></div>${mandatory?badge('mandatory'):badge('optional')}</article>`;}).join(''):emptyState('Catalog unavailable','Load the shipped component catalog before authoring a Blueprint.');
  renderBlueprintCatalogOptions();
  renderBlueprintOverlayOptions();
  renderBlueprintUpgradeOptions();
}
function renderBlueprintCatalogOptions(){
  const select=$('#blueprint-catalog-release'); if(!select)return;
  const project=state.projects.find(item=>item.id===$('#blueprint-project').value);
  const previous=select.value;
  const eligible=state.catalogReleases.filter(item=>item.state==='PUBLISHED'&&(item.visibility==='PLATFORM'||(project&&item.organizationId===project.organizationId)));
  select.innerHTML=`<option value="">Shipped catalog · legacy binding</option>${eligible.map(item=>`<option value="${esc(item.id)}">${esc(item.catalogName)}@${esc(item.catalogVersion)} · ${esc(item.channel)} · ${esc(item.visibility)}</option>`).join('')}`;
  if(eligible.some(item=>item.id===previous))select.value=previous;
  select.disabled=!!state.blueprintEditorReleaseId;
}
async function loadBlueprintCatalogSelection(){
  const id=$('#blueprint-catalog-release').value;
  if(!id){state.blueprintCatalogComponents=null;renderBlueprintAuthoringOptions();return;}
  try{const detail=await api(`/api/v1/catalog-releases/${id}`);state.blueprintCatalogComponents=detail.components||[];renderBlueprintAuthoringOptions();}catch(error){state.blueprintCatalogComponents=null;toast(error.message,'error');}
}
function blueprintReleaseLabel(item){return `${item.blueprintName}@${item.blueprintVersion} · ${item.state}`;}
function renderBlueprintUpgradeOptions(){
  const select=$('#blueprint-upgrade-from'); if(!select)return;
  const projectId=$('#blueprint-project').value, name=$('#blueprint-name').value.trim();
  const currentId=state.blueprintEditorReleaseId;
  const eligible=state.blueprintReleases.filter(item=>item.id!==currentId&&item.projectId===projectId&&item.blueprintName===name&&['PUBLISHED','DEPRECATED'].includes(item.state));
  const selected=new Set([...select.selectedOptions].map(option=>option.value));
  select.innerHTML=eligible.length?eligible.map(item=>`<option value="${esc(item.id)}"${selected.has(item.id)?' selected':''}>${esc(blueprintReleaseLabel(item))}</option>`).join(''):'<option value="">No eligible published release</option>';
  select.disabled=!eligible.length;
}
function stableBlueprintJSON(value){const normalize=v=>Array.isArray(v)?v.map(normalize):(v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,normalize(v[k])])):v);return JSON.stringify(normalize(value));}
function blueprintFromEditor(){
  const architectures=[]; if($('#blueprint-arch-amd64').checked)architectures.push('amd64'); if($('#blueprint-arch-arm64').checked)architectures.push('arm64');
  const distributions=$$('#blueprint-distribution-list [data-blueprint-distribution]:checked').map(input=>input.value);
  const plans=[...$('#blueprint-tenant-plans').selectedOptions].map(option=>option.value).filter(Boolean);
  const approvalRequiredFor=$$('[data-blueprint-approval-risk]:checked').map(input=>input.value);
  return {apiVersion:$('#blueprint-api-version').value,kind:$('#blueprint-kind').value,metadata:{name:$('#blueprint-name').value.trim(),version:$('#blueprint-version').value.trim()},spec:{description:$('#blueprint-description').value.trim(),compatibility:{kubernetes:{minVersion:$('#blueprint-k8s-min').value,maxVersion:$('#blueprint-k8s-max').value},architectures,distributionProfiles:distributions},delivery:{mode:$('#blueprint-delivery-mode').value,repository:$('#blueprint-repository').value.trim(),revision:$('#blueprint-revision').value.trim(),revisionType:$('#blueprint-revision-type').value,ociRegistry:$('#blueprint-registry').value.trim()},components:componentSelectionsFromEditor(),tenancy:{mode:$('#blueprint-tenancy-mode').value,plans,deletionPolicy:$('#blueprint-deletion-policy').value},governance:{approvalRequiredFor,enforceDigestImages:$('#blueprint-enforce-digest-images').checked,allowPlaintextSecrets:$('#blueprint-allow-plaintext-secrets').checked},certification:{requiredLevel:$('#blueprint-certification').value,evidenceRetentionDays:Number($('#blueprint-evidence-days').value)},fieldOwnership:ownershipRulesFromEditor()}};
}
function applyBlueprintToVisualEditor(b){
  if(!b||typeof b!=='object')throw new Error('Blueprint JSON object is required.');
  $('#blueprint-api-version').value=b.apiVersion||'';$('#blueprint-kind').value=b.kind||'';$('#blueprint-name').value=b.metadata?.name||'';$('#blueprint-version').value=b.metadata?.version||'';$('#blueprint-description').value=b.spec?.description||'';$('#blueprint-k8s-min').value=b.spec?.compatibility?.kubernetes?.minVersion||'';$('#blueprint-k8s-max').value=b.spec?.compatibility?.kubernetes?.maxVersion||'';
  $('#blueprint-arch-amd64').checked=(b.spec?.compatibility?.architectures||[]).includes('amd64');$('#blueprint-arch-arm64').checked=(b.spec?.compatibility?.architectures||[]).includes('arm64');$('#blueprint-delivery-mode').value=b.spec?.delivery?.mode||'';$('#blueprint-repository').value=b.spec?.delivery?.repository||'';$('#blueprint-registry').value=b.spec?.delivery?.ociRegistry||'';$('#blueprint-revision-type').value=b.spec?.delivery?.revisionType||'';$('#blueprint-revision').value=b.spec?.delivery?.revision||'';$('#blueprint-tenancy-mode').value=b.spec?.tenancy?.mode||'';$('#blueprint-deletion-policy').value=b.spec?.tenancy?.deletionPolicy||'';$('#blueprint-certification').value=b.spec?.certification?.requiredLevel||'';$('#blueprint-evidence-days').value=b.spec?.certification?.evidenceRetentionDays||'';$('#blueprint-field-ownership').value=ownershipRulesText(b.spec?.fieldOwnership||[]);
  const risks=new Set(b.spec?.governance?.approvalRequiredFor||[]);$$('[data-blueprint-approval-risk]').forEach(input=>input.checked=risks.has(input.value));$('#blueprint-enforce-digest-images').checked=b.spec?.governance?.enforceDigestImages===true;$('#blueprint-allow-plaintext-secrets').checked=b.spec?.governance?.allowPlaintextSecrets===true;
  state.blueprintComponentDraft={};(b.spec?.components||[]).forEach(item=>{state.blueprintComponentDraft[item.name]={present:true,enabled:item.enabled===true,settingsText:JSON.stringify(item.settings||{},null,2)}});$('#blueprint-component-list').innerHTML='';renderBlueprintAuthoringOptions();
  const distributions=new Set(b.spec?.compatibility?.distributionProfiles||[]);$$('#blueprint-distribution-list [data-blueprint-distribution]').forEach(input=>input.checked=distributions.has(input.value));const plans=new Set(b.spec?.tenancy?.plans||[]);[...$('#blueprint-tenant-plans').options].forEach(option=>option.selected=plans.has(option.value));
}
let blueprintAuthoringStep = 1;
function blueprintStageForControl(control){
  const stage=control?.closest?.('[data-blueprint-stage]');
  return stage?Number(stage.dataset.blueprintStage||1):1;
}
function showBlueprintAuthoringStep(step,{focus=false}={}){
  const next=Math.max(1,Math.min(4,Number(step)||1)); blueprintAuthoringStep=next;
  $$('[data-blueprint-stage]').forEach(stage=>{stage.hidden=Number(stage.dataset.blueprintStage)!==next;});
  $$('[data-blueprint-step]').forEach(button=>{const current=Number(button.dataset.blueprintStep)===next;button.classList.toggle('current',current);button.setAttribute('aria-current',current?'step':'false');});
  if(focus){const heading=$(`[data-blueprint-stage="${next}"] .workflow-stage-heading h3`);if(heading){heading.tabIndex=-1;heading.focus({preventScroll:true});heading.scrollIntoView({block:'start',behavior:'smooth'});}}
}
function validateBlueprintStage(step,{announce=true}={}){
  const stage=$(`[data-blueprint-stage="${step}"]`);if(!stage)return true;
  const invalid=$$('input,select,textarea',stage).find(control=>!control.disabled&&!control.checkValidity());
  if(invalid){showBlueprintAuthoringStep(step);invalid.reportValidity();invalid.focus();return false;}
  if(step===2&&!$('#blueprint-arch-amd64').checked&&!$('#blueprint-arch-arm64').checked){if(announce)toast('Select at least one architecture.','error');showBlueprintAuthoringStep(2);$('#blueprint-arch-amd64').focus();return false;}
  if(step===2&&!$$('#blueprint-distribution-list [data-blueprint-distribution]:checked').length){if(announce)toast('Select at least one distribution profile.','error');showBlueprintAuthoringStep(2);return false;}
  if(step===3&&!$('#blueprint-tenant-plans').selectedOptions.length){if(announce)toast('Select at least one tenant plan.','error');showBlueprintAuthoringStep(3);$('#blueprint-tenant-plans').focus();return false;}
  return true;
}
function validateBlueprintThrough(targetStep){for(let step=1;step<targetStep;step++){if(!validateBlueprintStage(step))return false;}return true;}
$$('[data-blueprint-step]').forEach(button=>button.addEventListener('click',()=>{const target=Number(button.dataset.blueprintStep);if(target>blueprintAuthoringStep&&!validateBlueprintThrough(target))return;showBlueprintAuthoringStep(target,{focus:true});}));
$$('[data-blueprint-step-next]').forEach(button=>button.addEventListener('click',()=>{const target=Number(button.dataset.blueprintStepNext);if(!validateBlueprintStage(blueprintAuthoringStep))return;showBlueprintAuthoringStep(target,{focus:true});}));
$$('[data-blueprint-step-back]').forEach(button=>button.addEventListener('click',()=>showBlueprintAuthoringStep(Number(button.dataset.blueprintStepBack),{focus:true})));
showBlueprintAuthoringStep(1);

function blueprintEditorValid(){
  for(let step=1;step<=4;step++){if(!validateBlueprintStage(step))return false;}
  return true;
}
function blueprintEditorHasUnsavedChanges(){return dirtyWithin($('#blueprint-release-form'))||$('#blueprint-authoring-json')?.dataset.dirty==='true';}
function clearBlueprintEditorDirty(){clearDirtyForms($('#blueprint-release-form'));const json=$('#blueprint-authoring-json');if(json)delete json.dataset.dirty;}
async function confirmDiscardBlueprintEditor(message){if(!blueprintEditorHasUnsavedChanges())return true;if(!await confirmAction('Discard unsaved Blueprint changes?',message,true))return false;clearBlueprintEditorDirty();return true;}
function resetBlueprintEditor(){
  state.blueprintEditorReleaseId=null; state.blueprintEditorRevision=0; state.blueprintCatalogComponents=null; state.blueprintComponentDraft={}; $('#blueprint-release-form').reset(); $('#blueprint-field-ownership').value=ownershipRulesText(defaultBlueprintOwnershipRules); $('#blueprint-api-version').value='platform.4so.io/v1alpha1'; $('#blueprint-kind').value='PlatformBlueprint'; $('#blueprint-delivery-mode').value='gitops'; $('#blueprint-tenancy-mode').value='namespace'; $('#blueprint-deletion-policy').value='approval-and-backup-required'; $('#blueprint-enforce-digest-images').checked=true; $('#blueprint-allow-plaintext-secrets').checked=false; $$('[data-blueprint-approval-risk]').forEach(input=>input.checked=['high','critical'].includes(input.value)); $('#blueprint-resolution-preview').innerHTML='';
  $('#blueprint-project').disabled=!state.projects.length; $('#blueprint-catalog-release').disabled=false; $('#blueprint-source-release').disabled=false; $('#blueprint-source-release').value=''; $('#blueprint-name').readOnly=false; $('#blueprint-version').readOnly=false;
  $('#blueprint-editor-state').className='badge neutral'; $('#blueprint-editor-state').textContent='NEW DRAFT'; $('#blueprint-release-save').textContent=state.locale==='fa'?'ایجاد Draft':'Create draft release';
  renderBlueprintAuthoringOptions(); clearBlueprintEditorDirty(); showBlueprintAuthoringStep(1);
}
async function populateBlueprintEditor(view){
  const release=view.release, b=view.baseBlueprint||view.blueprint; state.blueprintEditorReleaseId=release.id; state.blueprintEditorRevision=release.revision;
  $('#blueprint-project').value=release.projectId; $('#blueprint-project').disabled=true; state.blueprintCatalogComponents=null; renderBlueprintCatalogOptions(); $('#blueprint-catalog-release').value=release.catalogReleaseId||''; $('#blueprint-catalog-release').disabled=true; if(release.catalogReleaseId){try{const detail=await api(`/api/v1/catalog-releases/${release.catalogReleaseId}`);state.blueprintCatalogComponents=detail.components||[];}catch(error){toast(error.message,'error');}} $('#blueprint-name').value=b.metadata?.name||''; $('#blueprint-name').readOnly=true; $('#blueprint-version').value=b.metadata?.version||''; $('#blueprint-version').readOnly=true;
  applyBlueprintToVisualEditor(b); $('#blueprint-provider-overlay').value=view.revision?.providerOverlayId||''; $('#blueprint-environment-overlay').value=view.revision?.environmentOverlayId||''; $('#blueprint-source-release').value=release.sourceReleaseId||''; $('#blueprint-source-release').disabled=true;
  renderBlueprintUpgradeOptions(); const edges=new Set(release.upgradeFromIds||[]); [...$('#blueprint-upgrade-from').options].forEach(option=>option.selected=edges.has(option.value));
  $('#blueprint-editor-state').className=`badge ${statusClass(release.state)}`; $('#blueprint-editor-state').textContent=`${release.state} · r${release.revision}`; $('#blueprint-release-save').textContent=state.locale==='fa'?'ذخیره Revision جدید':'Save new immutable revision';
  clearBlueprintEditorDirty(); showBlueprintAuthoringStep(1); $('#blueprint-release-form').scrollIntoView({behavior:'smooth',block:'start'});
}
function renderBlueprintSourceOptions(){const select=$('#blueprint-source-release');if(!select)return;const previous=select.value;const eligible=state.blueprintReleases.filter(item=>item.id!==state.blueprintEditorReleaseId&&['PUBLISHED','DEPRECATED'].includes(item.state));select.innerHTML=`<option value="">No source release</option>${eligible.map(item=>`<option value="${esc(item.id)}">${esc(blueprintReleaseLabel(item))}</option>`).join('')}`;if(eligible.some(item=>item.id===previous))select.value=previous;select.disabled=!!state.blueprintEditorReleaseId;}
function renderBlueprintCompareOptions(){
  const options=state.blueprintReleases;
  for(const id of ['#blueprint-compare-left','#blueprint-compare-right'])setOptions($(id),options,item=>item.id,item=>blueprintReleaseLabel(item),'No releases');
  if(options.length>1&&!$('#blueprint-compare-right').value)$('#blueprint-compare-right').value=options[1].id;
}
function renderBlueprintReleases(){
  const projectById=new Map(state.projects.map(item=>[item.id,item]));
  $('#blueprint-release-grid').innerHTML=state.blueprintReleases.length?latest(state.blueprintReleases).map(item=>{const project=projectById.get(item.projectId);let actions=`<button type="button" class="secondary small-button" data-blueprint-action="inspect" data-id="${esc(item.id)}">Inspect</button>`;if(item.state==='DRAFT')actions+=`<button type="button" class="secondary small-button" data-blueprint-action="edit" data-id="${esc(item.id)}">Edit draft</button><button type="button" class="primary small-button" data-blueprint-action="review" data-id="${esc(item.id)}">Submit review</button>`;if(item.state==='REVIEW')actions+=`<button type="button" class="secondary small-button" data-blueprint-action="request-changes" data-id="${esc(item.id)}">Request changes</button><button type="button" class="primary small-button" data-blueprint-action="publish" data-id="${esc(item.id)}">Publish</button>`;if(['PUBLISHED','DEPRECATED','REVOKED'].includes(item.state))actions+=`<button type="button" class="secondary small-button" data-blueprint-action="clone" data-id="${esc(item.id)}">Clone</button>`;if(item.state==='PUBLISHED')actions+=`<button type="button" class="secondary small-button" data-blueprint-action="deprecate" data-id="${esc(item.id)}">Deprecate</button><button type="button" class="danger small-button" data-blueprint-action="revoke" data-id="${esc(item.id)}">Revoke</button>`;if(item.state==='DEPRECATED')actions+=`<button type="button" class="danger small-button" data-blueprint-action="revoke" data-id="${esc(item.id)}">Revoke</button>`;return `<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.blueprintName)} <span class="technical">${esc(item.blueprintVersion)}</span></h3><div class="resource-meta">${badge(item.state)}${badge(item.planStatus||'unknown')}${item.executionReady?badge('execution-ready'):badge('planning-only')}</div></div></div><p>${esc(project?.displayName||project?.name||item.projectId)}</p><div class="resource-details">${detailRow('Revision',`r${item.revision}`)}${detailRow('Blueprint digest',shortDigest(item.currentBlueprintDigest))}${detailRow('Catalog digest',shortDigest(item.catalogDigest))}${detailRow('Upgrade sources',(item.upgradeFromIds||[]).length)}${detailRow('Requested by',item.requestedBy||'—')}${detailRow('Published',formatDate(item.publishedAt))}</div><div class="resource-actions">${actions}</div></article>`;}).join(''):emptyState('No Blueprint releases','Create a project, then author the first real Blueprint release from this page.');
  renderBlueprintCompareOptions();
}
async function loadBlueprints(){
  try{
    const [catalog,plans,projects,releases,catalogReleases,overlays,authoringContract]=await Promise.all([softApi('/api/v1/catalog/components',[],'catalog'),softApi('/api/v1/tenancy/plans',[],'tenancy plans'),softApi('/api/v1/projects',[],'projects'),softApi('/api/v1/blueprint-releases',[],'blueprint releases'),softApi('/api/v1/catalog-releases',[],'catalog releases'),softApi('/api/v1/blueprint-overlays',[],'blueprint overlays'),softApi('/api/v1/blueprints/authoring-contract',{},'authoring contract')]);
    Object.assign(state,{catalog,tenantPlans:plans,projects,blueprintReleases:releases,catalogReleases,blueprintOverlays:overlays,blueprintAuthoringContract:authoringContract});
    prerequisite($('#blueprint-prerequisite'),projects.length>0,'A project is required before a Blueprint release can be authored.','workspace','Create a project');
    if(!state.blueprintEditorReleaseId)resetBlueprintEditor(); else renderBlueprintAuthoringOptions();
    renderBlueprintOverlays(); renderBlueprintSourceOptions(); renderBlueprintParitySummary();
    renderBlueprintReleases();
  }catch(error){$('#blueprint-release-grid').innerHTML=errorState(error.message);toast(error.message,'error');}
}
$('#blueprint-overlay-form').onsubmit=async event=>{
  event.preventDefault();const form=event.currentTarget;if(!form.reportValidity())return;
  try{const changes=parseOverlayChanges();if(!changes.length){toast('Add at least one overlay change.','error');return;}await api('/api/v1/blueprint-overlays',{method:'POST',body:{projectId:$('#blueprint-overlay-project').value,name:$('#blueprint-overlay-name').value.trim(),version:$('#blueprint-overlay-version').value.trim(),scope:$('#blueprint-overlay-scope').value,scopeKey:$('#blueprint-overlay-key').value.trim(),changes}});toast('Immutable overlay created.');form.reset();await loadBlueprints();}catch(error){toast(error.message,'error');}
};
$('#blueprint-resolve-preview').onclick=async()=>{
  try{if(!blueprintEditorValid())return;const blueprint=blueprintFromEditor();const result=await api('/api/v1/blueprints/resolve',{method:'POST',body:{projectId:$('#blueprint-project').value,catalogReleaseId:$('#blueprint-catalog-release').value||undefined,providerOverlayId:$('#blueprint-provider-overlay').value||undefined,environmentOverlayId:$('#blueprint-environment-overlay').value||undefined,blueprint}});const changed=(result.resolution?.fields||[]).filter(item=>item.effectiveOwner!=='BLUEPRINT_BASE');$('#blueprint-resolution-preview').innerHTML=`<div class="success-banner"><strong>Resolved preview</strong> · ${changed.length} delegated fields changed · ${esc(result.plan?.status||'unknown')}</div><div class="activity-list">${changed.map(item=>`<div class="activity-item"><div class="activity-main"><div><strong class="technical">${esc(item.path)}</strong><small>${esc(item.policy)} · ${esc(item.effectiveOwner)}</small></div></div>${badge(item.effectiveOwner)}</div>`).join('')}</div>`;}catch(error){$('#blueprint-resolution-preview').innerHTML=errorState(error.message);toast(error.message,'error');}
};
$('#blueprint-export-json').onclick=()=>{try{const b=blueprintFromEditor();$('#blueprint-authoring-json').value=JSON.stringify(b,null,2);delete $('#blueprint-authoring-json').dataset.dirty;$('#blueprint-parity-result').innerHTML='<div class="inline-summary">Visual editor exported to strict Blueprint JSON.</div>';}catch(error){toast(error.message,'error');}};
$('#blueprint-import-json').onclick=()=>{try{const raw=$('#blueprint-authoring-json').value.trim();if(!raw)throw new Error('Paste Blueprint JSON first.');const b=JSON.parse(raw);applyBlueprintToVisualEditor(b);$('#blueprint-release-form').dataset.dirty='true';delete $('#blueprint-authoring-json').dataset.dirty;$('#blueprint-parity-result').innerHTML='<div class="success-banner"><strong>Imported</strong> · all API fields were mapped into visual controls.</div>';toast('Blueprint JSON imported into the visual editor.');}catch(error){toast(error.message,'error');}};
$('#blueprint-verify-parity').onclick=async()=>{try{const visual=blueprintFromEditor();const result=await api('/api/v1/blueprints/authoring-roundtrip',{method:'POST',body:visual});const visualCanonical=stableBlueprintJSON(visual),apiCanonical=stableBlueprintJSON(result.blueprint);const same=visualCanonical===apiCanonical;$('#blueprint-authoring-json').value=JSON.stringify(result.blueprint,null,2);delete $('#blueprint-authoring-json').dataset.dirty;$('#blueprint-parity-result').innerHTML=`<div class="${same?'success-banner':'warning-banner'}"><strong>${same?'Exact round-trip PASS':'Round-trip mismatch'}</strong> · ${esc(result.method)} · ${esc(result.fieldCount)} fields · <span class="technical">${esc(result.digest)}</span> · validation ${result.validation?.valid?'PASS':'FAILED'}</div>`;if(!same)throw new Error('Visual/API canonical JSON mismatch.');}catch(error){toast(error.message,'error');}};
$('#blueprint-name').addEventListener('input',renderBlueprintUpgradeOptions); $('#blueprint-project').addEventListener('change',()=>{state.blueprintCatalogComponents=null;renderBlueprintCatalogOptions();renderBlueprintOverlayOptions();renderBlueprintUpgradeOptions();}); $('#blueprint-catalog-release').addEventListener('change',loadBlueprintCatalogSelection);
$('#blueprint-release-reset').onclick=async()=>{if(!await confirmDiscardBlueprintEditor('Reset the Blueprint editor and discard all unsaved visual/JSON changes?'))return;resetBlueprintEditor();};
$('#blueprint-release-form').onsubmit=async event=>{
  event.preventDefault(); if(!blueprintEditorValid())return;
  const blueprint=blueprintFromEditor(); const upgradeFromIds=[...$('#blueprint-upgrade-from').selectedOptions].map(option=>option.value).filter(Boolean);
  try{let result;if(state.blueprintEditorReleaseId){result=await api(`/api/v1/blueprint-releases/${state.blueprintEditorReleaseId}/draft`,{method:'PUT',headers:{'If-Match':`"${state.blueprintEditorRevision}"`},body:{blueprint,upgradeFromIds,providerOverlayId:$('#blueprint-provider-overlay').value,environmentOverlayId:$('#blueprint-environment-overlay').value}});}else{result=await api('/api/v1/blueprint-releases',{method:'POST',body:{projectId:$('#blueprint-project').value,catalogReleaseId:$('#blueprint-catalog-release').value||undefined,sourceReleaseId:$('#blueprint-source-release').value||undefined,providerOverlayId:$('#blueprint-provider-overlay').value||undefined,environmentOverlayId:$('#blueprint-environment-overlay').value||undefined,blueprint,upgradeFromIds}});}toast(state.blueprintEditorReleaseId?'Immutable draft revision saved.':'Blueprint draft release created.');state.blueprintEditorReleaseId=result.release.id;state.blueprintEditorRevision=result.release.revision;await loadBlueprints();const refreshed=await api(`/api/v1/blueprint-releases/${result.release.id}`);await populateBlueprintEditor(refreshed);}catch(error){toast(error.message,'error');}
};
$('#blueprint-release-grid').onclick=async event=>{
  const button=event.target.closest('[data-blueprint-action]');if(!button)return;const item=state.blueprintReleases.find(row=>row.id===button.dataset.id);if(!item)return;const action=button.dataset.blueprintAction;
  const replacesEditor=action==='edit'||action==='clone'||(state.blueprintEditorReleaseId===item.id&&!['inspect'].includes(action));
  if(replacesEditor&&!await confirmDiscardBlueprintEditor(`Continue with ${action} for ${item.blueprintName}@${item.blueprintVersion} and discard the current unsaved Blueprint editor state?`))return;
  try{
    if(action==='inspect'||action==='edit'){const view=await api(`/api/v1/blueprint-releases/${item.id}`);if(action==='edit'){await populateBlueprintEditor(view);return;}showDetails(`${item.blueprintName}@${item.blueprintVersion}`,`<dl class="key-value"><dt>State</dt><dd>${badge(item.state)}</dd><dt>Release revision</dt><dd class="technical">${esc(item.revision)}</dd><dt>Immutable revision</dt><dd class="technical">${esc(view.revision?.id||'—')}</dd><dt>Blueprint digest</dt><dd class="technical">${esc(item.currentBlueprintDigest)}</dd><dt>Catalog release</dt><dd class="technical">${esc(item.catalogReleaseId||'shipped legacy')}</dd><dt>Catalog digest</dt><dd class="technical">${esc(item.catalogDigest)}</dd><dt>Plan status</dt><dd>${esc(item.planStatus||'—')}</dd><dt>Execution ready</dt><dd>${item.executionReady?'yes':'no'}</dd><dt>Provider overlay</dt><dd class="technical">${esc(view.revision?.providerOverlayId||'—')}</dd><dt>Environment overlay</dt><dd class="technical">${esc(view.revision?.environmentOverlayId||'—')}</dd><dt>Overlay digest</dt><dd class="technical">${esc(view.revision?.overlayDigest||'—')}</dd><dt>Ownership digest</dt><dd class="technical">${esc(view.revision?.ownershipDigest||'—')}</dd></dl><details open><summary>Resolved Blueprint</summary><pre class="code-block technical" dir="ltr">${esc(JSON.stringify(view.blueprint,null,2))}</pre></details>`);return;}
    if(action==='clone'){const values=await askFields('Clone Blueprint release',[{name:'name',label:'Blueprint name',value:item.blueprintName},{name:'version',label:'New semantic version',value:''}],'Create draft clone');if(!values)return;const result=await api(`/api/v1/blueprint-releases/${item.id}/clone`,{method:'POST',body:{name:values.name,version:values.version}});toast('Draft clone created with immutable source reference.');await loadBlueprints();const view=await api(`/api/v1/blueprint-releases/${result.release.id}`);await populateBlueprintEditor(view);return;}
    const messages={review:['Submit for review',`Freeze ${item.blueprintName}@${item.blueprintVersion} for review?`,false],'request-changes':['Return to draft',`Return ${item.blueprintName}@${item.blueprintVersion} to DRAFT for changes?`,false],publish:['Publish Blueprint',`Publish immutable ${item.blueprintName}@${item.blueprintVersion}?`,false],deprecate:['Deprecate Blueprint',`Mark ${item.blueprintName}@${item.blueprintVersion} deprecated? Existing history remains available.`,false],revoke:['Revoke Blueprint',`Revoke ${item.blueprintName}@${item.blueprintVersion}? It cannot transition back to an active state.`,true]};const config=messages[action];if(!config)return;if(!await confirmAction(config[0],config[1],config[2]))return;await api(`/api/v1/blueprint-releases/${item.id}/${action}`,{method:'POST',headers:{'If-Match':`"${item.revision}"`},body:{}});toast(`Blueprint ${action} accepted.`);if(state.blueprintEditorReleaseId===item.id)resetBlueprintEditor();await loadBlueprints();
  }catch(error){toast(error.message,'error');}
};
$('#blueprint-compare').onclick=async()=>{const left=$('#blueprint-compare-left').value,right=$('#blueprint-compare-right').value;if(!left||!right){toast('Select two releases to compare.','error');return;}try{const result=await api('/api/v1/blueprint-releases/compare',{method:'POST',body:{leftReleaseId:left,rightReleaseId:right}});$('#blueprint-compare-result').innerHTML=result.equal?'<div class="success-banner">Stored Blueprint payloads are identical.</div>':`<div class="inline-summary"><strong>${esc(result.differenceCount)} differences</strong></div><div class="activity-list">${(result.differences||[]).slice(0,100).map(diff=>`<div class="activity-item"><div class="activity-main"><div><strong class="technical">${esc(diff.path)}</strong><small>${esc(diff.kind)}</small></div></div>${badge(diff.kind)}</div>`).join('')}</div>${result.differenceCount>100?'<p class="inline-summary">First 100 differences shown.</p>':''}`;}catch(error){$('#blueprint-compare-result').innerHTML=errorState(error.message);toast(error.message,'error');}};

async function loadCatalog(){
  try{
    const [catalog,summary,releases,trustKeys,signer,organizations]=await Promise.all([softApi('/api/v1/catalog/components',[],'catalog'),softApi('/api/v1/catalog/summary',{},'catalog summary'),softApi('/api/v1/catalog-releases',[],'catalog releases'),softApi('/api/v1/catalog-trust-keys',[],'catalog trust keys'),softApi('/api/v1/catalog-governance/signing-identity',{},'catalog signer'),softApi('/api/v1/organizations',[],'organizations')]);
    Object.assign(state,{catalog,catalogReleases:releases,catalogTrustKeys:trustKeys,catalogSigningIdentity:signer,organizations});
    renderCatalogGovernance(summary);
  }catch(error){$('#catalog-release-grid').innerHTML=errorState(error.message);$('#catalog-grid').innerHTML=errorState(error.message);toast(error.message,'error');}
}
function catalogOrgName(id){const org=state.organizations.find(item=>item.id===id);return org?(org.displayName||org.name):id||'Platform';}
function nextCatalogChannel(channel){return {CANDIDATE:'RENDER',RENDER:'RUNTIME',RUNTIME:'PRODUCTION'}[channel]||'';}
function catalogSelectedComponents(){const selected=new Set($$('[data-catalog-component-select]:checked').map(input=>input.value));return state.catalog.filter(component=>selected.has(component.metadata.name));}
function updateCatalogSelectedCount(){const selected=catalogSelectedComponents();const resolved=selected.filter(component=>component.spec?.source?.resolved).length;const target=$('#catalog-release-source-count');if(target)target.textContent=`${selected.length} components · ${resolved} resolved`;return selected;}
function renderCatalogGovernance(summary={}){
  const signer=state.catalogSigningIdentity||{};
  const published=state.catalogReleases.filter(item=>item.state==='PUBLISHED').length, activeKeys=state.catalogTrustKeys.filter(item=>item.state==='ACTIVE').length;
  $('#catalog-summary').innerHTML=[['Components',summary.componentCount||state.catalog.length,`${summary.resolvedComponentCount||0} resolved · ${summary.unresolvedComponentCount??state.catalog.filter(c=>!c.spec?.source?.resolved).length} unresolved`],['Renderable',summary.renderableComponentCount||0,'embedded source bundles verified at startup'],['Governed releases',state.catalogReleases.length,`${published} published`],['Active trust keys',activeKeys,'Ed25519 verification authority'],['Catalog digest',shortDigest(summary.digest||''),'shipped inventory digest']].map(([label,value,detail])=>`<article class="metric-card"><strong${label==='Catalog digest'?' class="technical"':''}>${esc(value)}</strong><span>${esc(label)}</span><small>${esc(detail)}</small></article>`).join('');
  $('#catalog-signer').innerHTML=signer.available?`<strong>Signer ready</strong> · ${badge(signer.mode||'configured')} · <span class="technical">${esc(signer.fingerprint||'')}</span>`:'<strong>Signing disabled</strong> · configure PLATFORM_FACTORY_CATALOG_SIGNING_PRIVATE_KEY_B64 for OIDC environments.';
  prerequisite($('#catalog-prerequisite'),signer.available,'A catalog signing identity is required before releases can enter REVIEW.','services','Review system configuration');
  const orgOptions=`<option value="">Platform-wide trust</option>${state.organizations.map(org=>`<option value="${esc(org.id)}">${esc(org.displayName||org.name)} · private</option>`).join('')}`;
  const trustSel=$('#catalog-trust-organization'), previousTrust=trustSel.value; trustSel.innerHTML=orgOptions;if([...trustSel.options].some(o=>o.value===previousTrust))trustSel.value=previousTrust;trustSel.disabled=!signer.available;
  const releaseOrg=$('#catalog-release-organization'), previousOrg=releaseOrg.value;releaseOrg.innerHTML=state.organizations.length?state.organizations.map(org=>`<option value="${esc(org.id)}">${esc(org.displayName||org.name)}</option>`).join(''):'<option value="">No organizations</option>';if([...releaseOrg.options].some(o=>o.value===previousOrg))releaseOrg.value=previousOrg;
  const componentList=$('#catalog-release-component-list');
  componentList.innerHTML=state.catalog.length?state.catalog.map(component=>{const resolved=component.spec?.source?.resolved===true;const renderable=resolved&&component.spec?.source?.type==='embedded-native'&&component.spec?.delivery?.type==='native-manifest';return `<label class="activity-item"><span class="activity-main"><input type="checkbox" data-catalog-component-select value="${esc(component.metadata.name)}"${renderable?' checked':''}><span><strong>${esc(component.spec.displayName)}</strong><small>${technical(component.metadata.name)} · ${esc(component.spec.release)} · ${resolved?'resolved':'unresolved'}${renderable?' · embedded renderable':''}</small></span></span>${badge(component.spec.certification?.status||'candidate')}</label>`;}).join(''):emptyState('No shipped components','No source inventory is embedded.');
  $$('[data-catalog-component-select]',componentList).forEach(input=>input.addEventListener('change',updateCatalogSelectedCount));
  updateCatalogSelectedCount();
  $('#catalog-trust-grid').innerHTML=state.catalogTrustKeys.length?state.catalogTrustKeys.map(key=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(key.name)}</h3><div class="resource-meta">${badge(key.state)}${badge(key.organizationId?'PRIVATE':'PLATFORM')}</div></div></div><div class="resource-details">${detailRow('Scope',catalogOrgName(key.organizationId))}${detailRow('Fingerprint',key.fingerprint,true)}${detailRow('Algorithm',key.algorithm)}</div><div class="resource-actions"><button class="secondary" data-catalog-trust-action="impact" data-id="${esc(key.id)}">Impact</button>${key.state==='ACTIVE'?`<button class="danger" data-catalog-trust-action="revoke" data-id="${esc(key.id)}">Revoke trust</button>`:''}</div></article>`).join(''):emptyState('No trust keys','Register the configured signer at platform or organization scope.');
  const catalogReleaseRows=state.catalogReleases.map(item=>{const next=nextCatalogChannel(item.channel);let actions=`<button class="secondary small-button" data-catalog-action="inspect" data-id="${esc(item.id)}">Inspect</button>`;if(item.state==='DRAFT')actions+=`<button class="secondary small-button" data-catalog-action="refresh" data-id="${esc(item.id)}">Refresh</button><button class="primary small-button" data-catalog-action="review" data-id="${esc(item.id)}">Sign & review</button>`;if(item.state==='REVIEW')actions+=`<button class="secondary small-button" data-catalog-action="request-changes" data-id="${esc(item.id)}">Changes</button><button class="primary small-button" data-catalog-action="publish" data-id="${esc(item.id)}">Publish</button>`;if(item.state==='PUBLISHED'){if(['RENDER','RUNTIME','PRODUCTION'].includes(item.channel))actions+=`<button class="primary small-button" data-catalog-action="render" data-id="${esc(item.id)}">Render</button>`;if(next)actions+=`<button class="primary small-button" data-catalog-action="promote" data-id="${esc(item.id)}">Promote → ${esc(next)}</button>`;actions+=`<button class="secondary small-button" data-catalog-action="deprecate" data-id="${esc(item.id)}">Deprecate</button><button class="danger small-button" data-catalog-action="revoke" data-id="${esc(item.id)}">Revoke</button>`;}if(item.state==='DEPRECATED'){if(next)actions+=`<button class="secondary small-button" data-catalog-action="promote" data-id="${esc(item.id)}">Promote → ${esc(next)}</button>`;actions+=`<button class="danger small-button" data-catalog-action="revoke" data-id="${esc(item.id)}">Revoke</button>`;}return tableRow([
    tableCell(`<span class="cell-title">${esc(item.catalogName)} <span class="technical">${esc(item.catalogVersion)}</span></span><span class="cell-meta">${esc(catalogOrgName(item.organizationId))}</span>`),
    tableCell(`${badge(item.channel)} ${badge(item.state)}`,'status-cell'),
    tableCell(badge(item.visibility),'status-cell'),
    tableCell(`<span class="technical">${shortDigest(item.manifestDigest)}</span><span class="cell-meta">r${esc(item.revision)} · signer ${item.signingKeyFingerprint?shortDigest(item.signingKeyFingerprint):'not signed'}</span>`),
    tableCell(`<div class="row-actions">${actions}</div>`,'actions-cell')
  ]);});
  $('#catalog-release-grid').innerHTML=dataTable('Governed catalog releases',[{label:'Release / scope'},{label:'Channel / state'},{label:'Visibility'},{label:'Authority'},{label:'Actions'}],catalogReleaseRows,'No governed catalog releases','Create the first immutable CANDIDATE from the shipped component inventory.',{source:'catalog releases'});
  const componentRows=state.catalog.map(component=>tableRow([
    tableCell(`<span class="cell-title">${esc(component.spec.displayName)}</span><span class="cell-meta technical">${esc(component.metadata.name)} · ${esc(component.spec.release)}</span>`),
    tableCell(`${badge(component.spec.category)} ${badge(component.spec.risk)}`,'status-cell'),
    tableCell(badge(component.spec.certification?.status),'status-cell'),
    tableCell(`${esc(component.spec.wave)}`,'numeric'),
    tableCell(`<span class="cell-title">${esc(component.spec.supportTier||'—')}</span><span class="cell-meta">${component.spec.mandatory?'mandatory':'optional'} · ${component.spec.source?.resolved?'source resolved':'source unresolved'}</span>`)
  ]));
  $('#catalog-grid').innerHTML=dataTable('Shipped component source inventory',[{label:'Component'},{label:'Category / risk'},{label:'Certification'},{label:'Wave',className:'numeric'},{label:'Support / source'}],componentRows,'No shipped components','No catalog source records are embedded in this release.',{source:'catalog'});
  const privateMode=$('#catalog-release-visibility').value==='PRIVATE';$('#catalog-release-organization').disabled=!privateMode||!state.organizations.length;
}
$('#catalog-release-visibility').addEventListener('change',()=>{$('#catalog-release-organization').disabled=$('#catalog-release-visibility').value!=='PRIVATE'||!state.organizations.length;});
$('#catalog-trust-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const signer=state.catalogSigningIdentity;if(!signer?.available){toast('Catalog signer is not configured.','error');return;}try{await api('/api/v1/catalog-trust-keys',{method:'POST',body:{organizationId:$('#catalog-trust-organization').value||undefined,name:$('#catalog-trust-name').value.trim(),publicKey:signer.publicKey}});toast('Signer trust registered.');await loadCatalog();}catch(error){toast(error.message,'error');}};
$('#catalog-release-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const visibility=$('#catalog-release-visibility').value,organizationId=visibility==='PRIVATE'?$('#catalog-release-organization').value:'',components=catalogSelectedComponents();if(visibility==='PRIVATE'&&!organizationId){toast('Select an organization for a private catalog.','error');return;}if(!components.length){toast('Select at least one component for this release.','error');return;}try{await api('/api/v1/catalog-releases',{method:'POST',body:{organizationId:organizationId||undefined,catalogName:$('#catalog-release-name').value.trim(),catalogVersion:$('#catalog-release-version').value.trim(),visibility,channel:'CANDIDATE',components}});toast('Immutable catalog candidate created.');await loadCatalog();}catch(error){toast(error.message,'error');}};
$('#catalog-trust-grid').onclick=async event=>{const button=event.target.closest('[data-catalog-trust-action]');if(!button)return;const key=state.catalogTrustKeys.find(item=>item.id===button.dataset.id);if(!key)return;try{const impact=await api(`/api/v1/catalog-trust-keys/${key.id}/impact`);if(button.dataset.catalogTrustAction==='impact'){showDetails(`Trust impact · ${key.name}`,`<dl class="key-value"><dt>Catalog releases</dt><dd>${impact.catalogReleases?.length||0}</dd><dt>Blueprint releases</dt><dd>${impact.blueprintReleases?.length||0}</dd><dt>Affected targets</dt><dd>${impact.affectedTargetRefs?.length||0}</dd></dl><pre class="code-block technical" dir="ltr">${esc(JSON.stringify(impact,null,2))}</pre>`);return;}if(!await confirmAction('Revoke catalog trust',`Revoke ${key.name}? ${impact.catalogReleases?.length||0} catalog releases and ${impact.blueprintReleases?.length||0} Blueprint releases are currently linked to this key.`,true))return;await api(`/api/v1/catalog-trust-keys/${key.id}/revoke`,{method:'POST',headers:{'If-Match':`"${key.revision}"`},body:{}});toast('Catalog trust revoked.');await loadCatalog();}catch(error){toast(error.message,'error');}};
$('#catalog-release-grid').onclick=async event=>{const button=event.target.closest('[data-catalog-action]');if(!button)return;const item=state.catalogReleases.find(row=>row.id===button.dataset.id);if(!item)return;const action=button.dataset.catalogAction;try{if(action==='inspect'){const detail=await api(`/api/v1/catalog-releases/${item.id}`);showDetails(`${item.catalogName}@${item.catalogVersion} · ${item.channel}`,`<dl class="key-value"><dt>State</dt><dd>${badge(item.state)}</dd><dt>Visibility</dt><dd>${esc(item.visibility)}</dd><dt>Trust verified</dt><dd>${detail.trust?.verified?'yes':'no'}</dd><dt>Trust reason</dt><dd>${esc(detail.trust?.reason||'verified')}</dd><dt>Admission</dt><dd>${detail.admission?.eligible?'eligible':'blocked'}</dd><dt>Manifest</dt><dd class="technical">${esc(item.manifestDigest)}</dd></dl>${detail.admission?.blockers?.length?`<div class="warning-banner"><strong>Channel blockers</strong><ul>${detail.admission.blockers.map(v=>`<li>${esc(v)}</li>`).join('')}</ul></div>`:'<div class="success-banner">Channel admission requirements are satisfied.</div>'}${detail.admission?.imageMirrors?.length?`<details open><summary>Runtime image mirrors</summary><div class="resource-details">${detail.admission.imageMirrors.map(m=>`${detailRow('Source',m.sourceReference||'unknown',true)}${detailRow('Mirror',m.mirrorReference||'not mirrored',true)}${detailRow('Registry status',m.available?'verified':(m.requiredForChannel?'required / unavailable':'not required for this channel'))}${m.error?detailRow('Mirror error',m.error):''}`).join('')}</div></details>`:''}<details><summary>Immutable components</summary><pre class="code-block technical" dir="ltr">${esc(JSON.stringify(detail.components,null,2))}</pre></details>`);return;}if(action==='refresh'){const detail=await api(`/api/v1/catalog-releases/${item.id}`);const names=new Set((detail.components||[]).map(component=>component.metadata.name));const refreshed=state.catalog.filter(component=>names.has(component.metadata.name));if(refreshed.length!==names.size){toast('One or more source components no longer exist in the shipped inventory.','error');return;}await api(`/api/v1/catalog-releases/${item.id}/draft`,{method:'PUT',headers:{'If-Match':`"${item.revision}"`},body:{components:refreshed}});toast('Draft source refreshed without changing its component set.');await loadCatalog();return;}if(action==='render'){const namespace=$('#catalog-render-namespace').value.trim();if(!namespace||!$('#catalog-render-namespace').reportValidity()){toast('Enter a valid render namespace.','error');return;}const rendered=await api(`/api/v1/catalog-releases/${item.id}/render`,{method:'POST',body:{namespace}});showDetails(`Rendered catalog · ${item.catalogName}@${item.catalogVersion}`,`<div class="success-banner"><strong>Deterministic render complete</strong> · ${esc(rendered.resourceCount)} Kubernetes resources · <span class="technical">${esc(rendered.renderedDigest)}</span></div><dl class="key-value"><dt>Namespace</dt><dd class="technical">${esc(rendered.namespace)}</dd><dt>Catalog manifest</dt><dd class="technical">${esc(rendered.manifestDigest)}</dd><dt>Channel</dt><dd>${badge(rendered.channel)}</dd></dl>${rendered.imageMirrors&&Object.keys(rendered.imageMirrors).length?`<details open><summary>Verified runtime image rewrites</summary><pre class="code-block technical" dir="ltr">${esc(JSON.stringify(rendered.imageMirrors,null,2))}</pre></details>`:''}<details open><summary>Rendered resources</summary><pre class="code-block technical" dir="ltr">${esc(JSON.stringify(rendered.resources,null,2))}</pre></details><details><summary>Source evidence</summary><pre class="code-block technical" dir="ltr">${esc(JSON.stringify(rendered.components,null,2))}</pre></details>`);return;}if(action==='promote'){await api(`/api/v1/catalog-releases/${item.id}/promote`,{method:'POST',body:{}});toast(`Promotion draft created for ${nextCatalogChannel(item.channel)}.`);await loadCatalog();return;}const config={review:['Sign and submit review',`Sign ${item.catalogName}@${item.catalogVersion} for ${item.channel} review?`,false],'request-changes':['Return catalog to draft','Return this signed review to DRAFT and clear its signature?',false],publish:['Publish catalog release',`Publish this immutable ${item.channel} catalog release?`,false],deprecate:['Deprecate catalog release','Deprecate this catalog release while preserving history?',false],revoke:['Revoke catalog release','Revoke this catalog release permanently?',true]}[action];if(!config)return;if(!await confirmAction(...config))return;await api(`/api/v1/catalog-releases/${item.id}/${action}`,{method:'POST',headers:{'If-Match':`"${item.revision}"`},body:{}});toast(`Catalog ${action} accepted.`);await loadCatalog();}catch(error){toast(error.message,'error');}};


function renderBlueprintResult(body,isPlan){
  $('#blueprint-result-panel').hidden=false;
  $('#blueprint-result-summary').textContent=isPlan?`${body.status||'unknown'} · executable ${body.executable===true?'yes':'no'} · ${(body.blockers||[]).length} blockers`:`${body.valid?'Valid':'Invalid'} · ${(body.findings||[]).length} findings`;
  if(isPlan){$('#blueprint-result').innerHTML=`${(body.blockers||[]).length?`<div class="warning-banner"><strong>Blockers</strong><ul>${body.blockers.map(item=>`<li>${esc(item)}</li>`).join('')}</ul></div>`:''}<div class="timeline">${(body.steps||[]).map(step=>`<div class="timeline-step"><span class="timeline-dot">${esc(step.order||'•')}</span><div><h4>${esc(step.title||step.name||step.key)}</h4><p>${esc(step.phase||step.stage||step.action||'planning')}</p></div></div>`).join('')}</div><details><summary>Technical result</summary><pre class="code-block technical" dir="ltr">${esc(JSON.stringify(body,null,2))}</pre></details>`;}else{$('#blueprint-result').innerHTML=(body.findings||[]).length?`<div class="activity-list">${body.findings.map(item=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">${item.severity==='error'?'!':'i'}</span><div><strong>${esc(item.code||item.severity)}</strong><small>${esc(item.path||'blueprint')} · ${esc(item.message)}</small></div></div>${badge(item.severity)}</div>`).join('')}</div>`:'<div class="inline-summary">Blueprint is valid against the shipped catalog.</div>';}
}
async function runBlueprint(path){const input=$('#blueprint-input').value.trim();if(!input){toast('Paste a Blueprint JSON document first.','error');return;}let body;try{body=JSON.parse(input);}catch(error){toast(`Invalid JSON: ${error.message}`,'error');return;}try{const result=await api(path,{method:'POST',body});renderBlueprintResult(result,path.endsWith('/plans'));toast(path.endsWith('/plans')?'Planning result created.':'Blueprint validation completed.');}catch(error){toast(error.message,'error');}}
function renderCompatibilityResult(result){
  const decision=result?.decision||{};const checks=decision.checks||[];const pass=decision.status==='PASS';
  $('#compatibility-result').innerHTML=`<div class="${pass?'success-banner':'warning-banner'}"><strong>${pass?'Compatible':'Compatibility blocked'}</strong> · ${esc(result?.authority||'PLATFORM_COMPATIBILITY_MATRIX_V1')} · ${esc(checks.filter(item=>item.status==='PASS').length)}/${esc(checks.length)} checks PASS${decision.digest?` · <span class="technical">${esc(shortDigest(decision.digest))}</span>`:''}</div>${checks.length?`<div class="activity-list">${checks.map(item=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">${item.status==='PASS'?'✓':'!'}</span><div><strong>${esc(item.dimension||item.name||'constraint')}</strong><small>${esc(item.constraint||item.expected||'')} ${item.target?`· target ${esc(item.target)}`:''}${item.message?` · ${esc(item.message)}`:''}</small></div></div>${badge(item.status||'UNKNOWN')}</div>`).join('')}</div>`:''}`;
}
$('#compatibility-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const input=$('#blueprint-input').value.trim();if(!input){toast('Paste a Blueprint JSON document first.','error');return;}let blueprint;try{blueprint=JSON.parse(input);}catch(error){toast(`Invalid JSON: ${error.message}`,'error');return;}const target={kubernetesVersion:$('#compatibility-kubernetes').value.trim(),architecture:$('#compatibility-architecture').value,distribution:$('#compatibility-distribution').value,provider:$('#compatibility-provider').value};try{const result=await api('/api/v1/compatibility/evaluate',{method:'POST',body:{blueprint,target}});renderCompatibilityResult(result);toast('Compatibility evaluation completed.');}catch(error){if(error.body?.decision){renderCompatibilityResult(error.body);toast('Compatibility evaluation found blockers.','warning');}else toast(error.message,'error');}};
$('#validate').onclick=()=>runBlueprint('/api/v1/blueprints/validate');$('#plan').onclick=()=>runBlueprint('/api/v1/plans');$('#blueprint-clear').onclick=()=>{$('#blueprint-input').value='';delete $('#blueprint-input').dataset.dirty;$('#blueprint-result-panel').hidden=true;$('#compatibility-result').innerHTML='';};

const loaders={overview:loadOverview,workspace:loadWorkspace,installation:loadInstallation,clusters:loadClusters,providers:loadProviders,blueprints:loadBlueprints,marketplace:loadMarketplace,baselines:loadBaselines,verification:loadVerification,fleet:loadFleet,tenants:loadTenants,operations:loadOperations,ai:loadAI,lab:loadLab,notifications:loadNotifications,services:loadServices,catalog:loadCatalog,validator:async()=>{}};
const livePages=new Set(['overview','clusters','providers','marketplace','baselines','verification','fleet','tenants','operations','ai','notifications','services']);
function hasActiveWork(page = state.currentPage){
  const pageCollections={
    overview:[state.operations,state.baselineDeployments,state.verifications,state.closures,state.runtimeCertifications,state.providerClusters,state.marketplaceInstallations,state.tenants,state.driftScans,state.upgradeCampaigns,state.notificationDeliveries],
    clusters:[state.imports], providers:[state.providerClusters], marketplace:[state.marketplaceInstallations], baselines:[state.baselineDeployments],
    verification:[state.verifications,state.closures,state.runtimeCertifications], fleet:[state.driftScans,state.upgradeCampaigns], tenants:[state.tenants], operations:[state.operations], notifications:[state.notificationDeliveries]
  };
  return (pageCollections[page]||[]).some(items=>(items||[]).some(item=>/REQUESTED|PENDING|QUEUED|RUNNING|PLANNING|APPLYING|VERIFYING|UPGRADING|DELIVERING|PROVISIONING|RESIZING|SUSPENDING|RESUMING|DELETING|AWAITING_APPROVAL|PAUSE_REQUESTED|ROLLING/i.test(String(item.state||item.status||''))));
}
function markFormClean(form){if(form?.dataset)delete form.dataset.dirty;}
function markDirtyTarget(target){const form=target.closest?.('form');if(form?.closest('.page'))form.dataset.dirty='true';else if(target.matches?.('[data-dirty-guard]')&&target.closest?.('.page'))target.dataset.dirty='true';}
function dirtyWithin(root){if(!root)return false;if(root.matches?.('form[data-dirty="true"], [data-dirty-guard][data-dirty="true"]'))return true;return !!root.querySelector?.('form[data-dirty="true"], [data-dirty-guard][data-dirty="true"]');}
function clearDirtyForms(root=document){if(root.matches?.('form[data-dirty="true"]'))markFormClean(root);if(root.matches?.('[data-dirty-guard][data-dirty="true"]'))delete root.dataset.dirty;$$('form[data-dirty="true"]',root).forEach(markFormClean);$$('[data-dirty-guard][data-dirty="true"]',root).forEach(control=>delete control.dataset.dirty);}
async function confirmDiscardDirty(root,title,message){if(!dirtyWithin(root))return true;if(!await confirmAction(title,message,true))return false;clearDirtyForms(root);return true;}
function hasUnsavedChanges(){return !!$('.page.active form[data-dirty="true"], .page.active [data-dirty-guard][data-dirty="true"]');}
document.addEventListener('input',event=>markDirtyTarget(event.target));
document.addEventListener('change',event=>markDirtyTarget(event.target));
document.addEventListener('reset',event=>{const form=event.target;setTimeout(()=>markFormClean(form),0);});
document.addEventListener('submit',event=>{state.lastSubmittedForm=event.target;state.lastSubmittedAt=Date.now();},true);
document.addEventListener('pointerdown',event=>{if(event.target.closest?.('.page.active'))state.interactionHoldUntil=Date.now()+2000;},true);
document.addEventListener('keydown',event=>{if(event.target.closest?.('.page.active')&&['Enter',' ','Tab'].includes(event.key))state.interactionHoldUntil=Date.now()+1500;},true);
window.addEventListener('beforeunload',event=>{if(!hasUnsavedChanges())return;event.preventDefault();event.returnValue='';});
function userIsEditing(){const el=document.activeElement;const focused=!!el&&['INPUT','TEXTAREA','SELECT'].includes(el.tagName)&&!el.readOnly;const expanded=!!$('.page.active details[open]');const recentInteraction=Date.now()<state.interactionHoldUntil;return focused||hasUnsavedChanges()||expanded||recentInteraction;}
function scheduleAutoRefresh(){
  clearTimeout(state.autoRefreshTimer); const generation=++state.autoRefreshGeneration;
  if(!livePages.has(state.currentPage))return;
  const delay=hasActiveWork(state.currentPage)?8000:30000;
  state.autoRefreshTimer=setTimeout(async()=>{
    if(generation!==state.autoRefreshGeneration)return;
    const dialogOpen=$$('dialog').some(dialog=>dialog.open);
    if(document.visibilityState==='visible'&&!state.pageLoading&&!userIsEditing()&&!dialogOpen)await loadPage(state.currentPage,false,true);
    else scheduleAutoRefresh();
  },delay);
}
function ensureCollectionToolbar(list){
  if(!list)return;
  if(list.dataset.collectionTools==='true'){list._applyCollectionFilter?.();return;}
  const toolbar=document.createElement('div');toolbar.className='collection-toolbar';toolbar.hidden=true;
  const label=document.createElement('label');label.className='collection-filter';const span=document.createElement('span');
  const input=document.createElement('input');input.type='search';input.autocomplete='off';
  const count=document.createElement('span');count.className='collection-count';count.setAttribute('aria-live','polite');label.append(span,input);toolbar.append(label,count);list.insertAdjacentElement('beforebegin',toolbar);
  const localize=()=>{const filterLabel=state.locale==='fa'?'فیلتر رکوردهای بارگذاری‌شده':'Filter loaded records';span.textContent=filterLabel;input.placeholder=state.locale==='fa'?'جستجو در این فهرست':'Search this list';input.setAttribute('aria-label',filterLabel);};
  const apply=()=>{
    localize();
    let empty=list.querySelector(':scope > .filtered-empty-state');
    if(!empty){empty=document.createElement('div');empty.className='filtered-empty-state';empty.hidden=true;list.append(empty);}
    empty.textContent=state.locale==='fa'?'رکورد منطبق در داده بارگذاری‌شده وجود ندارد.':'No matching record in the loaded data.';
    const directRecords=[...list.children].filter(node=>node!==empty&&(node.classList.contains('resource-card')||node.classList.contains('activity-item')));
    const tableRecords=[...list.querySelectorAll(':scope > .data-table-shell tbody > tr[data-record-row]')];
    const records=directRecords.length?directRecords:tableRecords;
    if(records.length<8){const unavailable=!!list.querySelector(':scope > .unavailable-state');if(!unavailable)input.value='';toolbar.hidden=true;records.forEach(record=>record.hidden=false);empty.hidden=true;count.textContent=`${records.length}`;return;}
    toolbar.hidden=false;const query=input.value.trim().toLocaleLowerCase();let visible=0;
    records.forEach(record=>{const match=!query||record.textContent.toLocaleLowerCase().includes(query);record.hidden=!match;if(match)visible++;});
    empty.hidden=!query||visible!==0;count.textContent=query?`${visible} / ${records.length}`:`${records.length}`;
  };
  input.addEventListener('input',apply);list.dataset.collectionTools='true';list._applyCollectionFilter=apply;apply();
}
let collectionToolFrame=0;
const collectionObserver=new MutationObserver(()=>{cancelAnimationFrame(collectionToolFrame);collectionToolFrame=requestAnimationFrame(()=>{restoreDataTableSortPreferences($('#main-content'));$$('.record-list,[data-filterable="true"]').forEach(list=>{ensureCollectionToolbar(list);list._applyCollectionFilter?.();});});});
collectionObserver.observe($('#main-content'),{childList:true,subtree:true});
$$('.record-list,[data-filterable="true"]').forEach(ensureCollectionToolbar);

async function loadPage(page,manual=false,automatic=false){
  const loader=loaders[page];if(!loader)return false;if(state.pageLoading&&automatic)return false;
  if(state.pageLoadController)state.pageLoadController.abort();
  const controller=new AbortController(),generation=++state.pageLoadGeneration;state.pageLoadController=controller;
  state.pageLoading=true;state.degradedRequests=[];$('#refresh-current').disabled=true;
  const activePage=$(`#${page}.page`);if(activePage)activePage.setAttribute('aria-busy','true');$('#main-content').setAttribute('aria-busy','true');
  try{
    await loader();
    if(generation!==state.pageLoadGeneration||page!==state.currentPage)return false;
    restoreDataTableSortPreferences(activePage||document);applyAccessMode();renderDegradedState();if(manual)toast('Page refreshed.');
    return true;
  }
  catch(error){
    if(error?.name==='AbortError'||generation!==state.pageLoadGeneration)return false;
    renderDegradedState();if(error.sessionExpired)handleSessionExpired();else toast(error.message,'error');
    return false;
  }
  finally{
    if(activePage)activePage.setAttribute('aria-busy','false');
    if(generation===state.pageLoadGeneration){state.pageLoading=false;state.pageLoadController=null;$('#refresh-current').disabled=false;$('#main-content').setAttribute('aria-busy','false');scheduleAutoRefresh();}
  }
}
document.addEventListener('visibilitychange',async()=>{if(document.visibilityState==='visible'){await syncSessionAuthority({redirectOnUnauthorized:true});if(!state.sessionRedirectPending)scheduleAutoRefresh();}});


function applyConsoleTheme(theme){
  const resolved=['light','dark'].includes(theme)?theme:(window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');
  document.documentElement.dataset.theme=resolved;
  const toggle=$('#theme-toggle');if(toggle){toggle.setAttribute('aria-pressed',resolved==='dark'?'true':'false');toggle.title=resolved==='dark'?'Use light theme':'Use dark theme';}
}
function toggleConsoleTheme(){
  const next=document.documentElement.dataset.theme==='dark'?'light':'dark';
  localStorage.setItem('platformTheme',next);applyConsoleTheme(next);
}
function setupConsoleCommandPalette(){
  const trigger=$('#command-trigger');if(!trigger)return;
  const dialog=$('#command-palette');if(!dialog)return;
  const input=$('#command-palette-input'),results=$('#command-palette-results');
  const render=()=>{const q=input.value.trim().toLocaleLowerCase();const locale=state.locale==='fa'?'fa':'en';const items=Object.entries(pageTitles).map(([id,value])=>({id,group:value[locale][0],title:value[locale][1]})).filter(item=>!q||`${item.group} ${item.title} ${item.id}`.toLocaleLowerCase().includes(q)).slice(0,12);results.innerHTML=items.length?items.map((item,index)=>`<button type="button" data-command-page="${esc(item.id)}"${index===0?' class="current"':''}><span><strong>${esc(item.title)}</strong><small>${esc(item.group)}</small></span><span class="command-palette-arrow">→</span></button>`).join(''):emptyState('No matching destination','Try a cluster, fleet, AI, Lab, catalog or administration term.');};
  const open=()=>{render();dialog.showModal();requestAnimationFrame(()=>{input.focus();input.select();});};
  trigger.onclick=open;input.addEventListener('input',render);
  results.addEventListener('click',async event=>{const button=event.target.closest('[data-command-page]');if(!button)return;dialog.close();await navigate(button.dataset.commandPage);});
  input.addEventListener('keydown',event=>{const buttons=$$('[data-command-page]',results);if(!buttons.length)return;let index=buttons.findIndex(b=>b.classList.contains('current'));if(event.key==='ArrowDown'||event.key==='ArrowUp'){event.preventDefault();buttons[index]?.classList.remove('current');index=event.key==='ArrowDown'?(index+1)%buttons.length:(index-1+buttons.length)%buttons.length;buttons[index].classList.add('current');buttons[index].scrollIntoView({block:'nearest'});}else if(event.key==='Enter'){const current=buttons[index]||buttons[0];if(current){event.preventDefault();current.click();}}});
  document.addEventListener('keydown',event=>{if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='k'){event.preventDefault();dialog.open?input.focus():open();}});
}

async function init(){
  applyConsoleTheme(localStorage.getItem('platformTheme'));
  setupConsoleCommandPalette();
  applyLocale();
  await loadSession();
  const requested=location.hash.slice(1);
  await navigate(pageTitles[requested]?requested:'overview');
}
init();
