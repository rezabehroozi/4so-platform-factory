'use strict';

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const state = {
  locale: localStorage.getItem('platformLocale') || 'en',
  session: null,
  currentPage: 'overview',
  catalog: [], catalogReleases: [], catalogTrustKeys: [], catalogSigningIdentity: {}, blueprintCatalogComponents: null, blueprintAuthoringContract: null, blueprintComponentDraft: {}, profiles: [], installationIntegrations: {}, organizations: [], projects: [], clusters: [], imports: [], blueprintReleases: [], blueprintOverlays: [], blueprintEditorReleaseId: null, blueprintEditorRevision: 0, variableSchemas: [], platformPolicySets: [], platformTemplates: [], applicationWorkloadTypes: [], applicationCapabilityTraits: [], applicationResourceTypes: [], applicationWorkspaceProfiles: [], applicationReleases: [], applicationEnvironmentBindings: [], workspaces: [], workspaceBindings: [], finOpsRateCards: [], finOpsUsage: [], finOpsCostSummary: null, finOpsChargeback: null,
  baselines: [], baselineDeployments: [], verifications: [], closures: [], runtimeCertifications: [],
  fleetGroups: [], driftScans: [], upgradeCampaigns: [], recoveryCheckpoints: [], backupPolicies: [], dataProtectionRuns: [], fleetHealth: null, day2CampaignEngine: null, tenants: [], tenantPlans: [],
  clusterMaintenanceProfile: null, clusterMaintenanceWindows: [], clusterMaintenanceRuns: [], targetNodeLifecycleAuthority: null, currentMaintenanceClusterId: '', maintenanceLoadGeneration: 0, providerProfiles: [], providerClusters: [], virtualClusters: [], marketplaceOffers: [], marketplaceInstallations: [], recommendations: [],
  operations: [], audit: [], queueCenter: null, productLogs: null, workloadLogExplorer: null, workloadLogQuery: null, aiPolicy: {}, aiGuide: {}, aiRuns: [], aiLatestDiagnosis: null, aiServiceAccounts: [], aiAPITokens: {}, autopilotStatus: null, supportProfiles: [], installationRecoveryAuthority: null, notificationDestinations: [], notificationRoutes: [], notificationEvents: [], notificationDeliveries: [], notificationEventTypes: [], notificationProviderContracts: [], notificationRoutingPreview: null, externalRegistryAdmission: null, summary: {}, services: [], version: {}, gitRevisionFiles: {}, accessContext: null, resourceScopeRegistry: null, organizationMemberships: [], serviceAccounts: [], apiTokens: {}, identityAuthority: null, oidcGroupMappings: [], securityAudit: [], currentEntitlement: null, currentOEMProfile: null,
  degradedRequests: [], pageLoading: false, pageLoadController: null, pageLoadGeneration: 0, autoRefreshTimer: null, autoRefreshGeneration: 0, interactionHoldUntil: 0, lastSubmittedForm: null, lastSubmittedAt: 0, sessionRedirectPending: false, sessionRefreshPromise: null, permissionContextReady: false, gitProviders: [], gitCredentials: [], tableSortPreferences: {},
  globalScope: {organizationId: localStorage.getItem('platformScopeOrganization') || '', projectId: localStorage.getItem('platformScopeProject') || ''},
  scopeOrganizations: [], scopeProjects: [], scopeReady: false, scopeTransitioning: false,
  mutationOutcome: null, mcpDelegationArchitecture: null, managedOKDRuntime: {configured:false,requestCreationAllowed:false}
};

const fa = {
  'nav.platform':'پلتفرم','nav.operate':'عملیات','nav.system':'سیستم','nav.start':'شروع','nav.overview':'نمای کلی','nav.workspace':'سازمان‌ها و پروژه‌ها','nav.infrastructure':'زیرساخت','nav.installation':'برنامه‌ریزی نصب','nav.clusters':'کلاسترهای متصل','nav.providers':'چرخه عمر زیرساخت','nav.delivery':'تحویل پلتفرم','nav.blueprints':'نسخه‌های Blueprint','nav.marketplace':'مارکت‌پلیس','nav.baselines':'استقرار Baseline تأییدشده','nav.verification':'تأیید سلامت و بستن شواهد','nav.fleet':'مدیریت ناوگان و ارتقا','nav.commercial':'تجاری','nav.tenants':'Tenantها و برندینگ','nav.operations':'عملیات','nav.activity':'عملیات و ممیزی','nav.notifications':'اعلان‌ها و مسیریابی','nav.services':'سرویس‌های سیستم','nav.advanced':'پیشرفته','nav.catalog':'کاتالوگ','nav.validator':'ابزار برنامه‌ریزی Blueprint',
  'action.createServiceAccount':'ساخت حساب سرویس','action.grantAccess':'اعطا یا به‌روزرسانی دسترسی','action.revokeAccess':'لغو دسترسی','action.signout':'خروج','action.refresh':'بازخوانی','action.viewAll':'مشاهده همه','action.createOrg':'ایجاد سازمان','action.createProject':'ایجاد پروژه','action.createPlan':'ساخت برنامه','action.clear':'پاک‌کردن','action.createImport':'ساخت درخواست اتصال','action.copy':'کپی','action.verifyProfile':'تأیید پروفایل','action.createCluster':'ساخت درخواست کلاستر','action.getAdvisory':'دریافت پیشنهاد','action.createInstallPlan':'ساخت برنامه نصب','action.createLivePlan':'ساخت برنامه از وضعیت فعلی','action.runVerification':'اجرای بررسی سلامت','action.createClosure':'تکمیل شواهد تأیید','action.createFleet':'ایجاد Fleet','action.applyEntitlement':'اعمال مجوز تجاری','action.saveOEM':'ذخیره تنظیمات برند','action.createTenant':'ایجاد Tenant','action.validate':'اعتبارسنجی','action.cancel':'انصراف','action.confirm':'تأیید','action.saveDraft':'ایجاد پیش‌نویس','action.resetDraft':'پاک‌کردن فرم','action.compare':'مقایسه',
  'overview.authority':'مرکز کنترل پلتفرم خصوصی','flow.configure':'پیکربندی','flow.configureHelp':'Blueprintها، Baselineها و کاتالوگ','flow.build':'ایجاد یا واردکردن','flow.buildHelp':'پلتفرم‌ها و زیرساخت مقصد','flow.operate':'مدیریت Fleet','flow.operateHelp':'سلامت، مغایرت‌ها، نگه‌داری و ارتقا','flow.prove':'تأیید و بازیابی','flow.proveHelp':'عملیات، شواهد، ممیزی و گواهی‌های فنی','overview.heading':'وضعیت پلتفرم و کار بعدی','overview.description':'پیش از هر تغییر، وضعیت فعلی پلتفرم، موانع و عملیات در حال اجرا را بررسی کنید.','reliability.deliveryInsights':'بینش تحویل','reliability.deliveryInsightsHelp':'جریان استقرار مبتنی بر شواهد در ۳۰ روز گذشته. اگر شواهد استقرار یا زمان Commit منبع موجود نباشد، وضعیت ناشناخته باقی می‌ماند.','overview.readiness':'آمادگی مراحل راه‌اندازی','overview.readinessHelp':'وضعیت هر مرحله مستقیماً از دادهٔ واقعی API محاسبه می‌شود.','overview.attention':'نیازمند توجه','overview.attentionHelp':'خطاها و پیش‌نیازهایی که برای ادامه نیاز به رسیدگی دارند.','overview.recent':'فعالیت‌های اخیر','overview.recentHelp':'آخرین عملیات ثبت‌شده و رویدادهای ممیزی.',
  'workspace.automation':'هویت‌های خودکارسازی','workspace.automationHelp':'برای خودکارسازی، حساب سرویس و توکن API زمان‌دار بسازید. مقدار محرمانه فقط یک‌بار نمایش داده می‌شود و اختیار تأیید انسانی هرگز به حساب سرویس منتقل نمی‌شود.','workspace.heading':'سازمان‌ها و پروژه‌ها','workspace.description':'ساختار سازمان و پروژه‌ای را تعریف کنید که کلاسترها، Tenantها، زیرساخت‌ها و استقرارها زیر آن مدیریت می‌شوند.','workspace.createOrg':'ایجاد سازمان','workspace.createOrgHelp':'یک شناسهٔ ثابت برای سیستم و یک نام خوانا برای کاربران وارد کنید.','workspace.createProject':'ایجاد پروژه','workspace.createProjectHelp':'هر پروژه منابع، دسترسی‌ها و سابقهٔ عملیات خود را جدا نگه می‌دارد.','workspace.records':'رکوردهای سازمان و پروژه','workspace.recordsHelp':'می‌توانید نام نمایشی سازمان را بدون تغییر شناسهٔ منابع عوض کنید.','workspace.access':'دسترسی سازمانی','workspace.accessHelp':'دسترسی مؤثر خود را ببینید و اگر مدیر سازمان هستید، عضویت کاربران همان سازمان را بدون اعطای دسترسی سراسری مدیریت کنید.',
  'field.projectScope':'محدوده پروژه','field.productRole':'نقش محصول','field.subject':'شناسه هویت','field.organizationRole':'نقش سازمانی','field.machineName':'شناسه سیستمی','field.displayName':'نام نمایشی','field.organization':'سازمان','field.project':'پروژه','field.profile':'پروفایل','field.connectivity':'نوع اتصال','field.provider':'ارائه‌دهنده زیرساخت','field.nodes':'آدرس نودهای مدیریت','field.credentialRef':'مرجع اطلاعات دسترسی','field.sshUser':'کاربر SSH','field.storageClass':'StorageClass تکثیرشونده','field.endpoint':'نشانی عمومی','field.dnsZone':'زون DNS','field.tlsMode':'حالت TLS','field.certificateRef':'مرجع گواهی','field.adminEmail':'ایمیل مدیر Identity','field.objectStorageMode':'ذخیره‌سازی شیءگرا','field.objectStorageUrl':'نشانی سرویس سازگار با S3','field.bucket':'مخزن S3','field.prefix':'پیشوند مسیر','field.expiration':'مهلت درخواست اتصال','field.managementCluster':'کلاستر مدیریت','field.workerClass':'کلاس نود کاری','field.defaultVersion':'نسخه پیش‌فرض Kubernetes','field.series':'سری‌های major/minor مجاز','field.infrastructureProvider':'ارائه‌دهنده زیرساخت','field.infrastructureEndpoint':'نشانی vCenter','field.maxWorkers':'حداکثر نود کاری','field.providerProfile':'پروفایل زیرساخت تأییدشده','field.kubernetesVersion':'نسخه Kubernetes','field.controlPlane':'تعداد نود کنترل‌پلین','field.workers':'تعداد Worker','field.cluster':'کلاستر متصل','field.offer':'بسته منتشرشده','field.objective':'هدف پیشنهاد','field.baseline':'نسخه Baseline','field.namespace':'Namespace مقصد','field.baselineDeployment':'استقرار Baseline تأییدشده','field.clusters':'کلاسترهای متصل','field.edition':'Edition','field.brandName':'نام برند','field.productTitle':'عنوان محصول','field.supportUrl':'آدرس پشتیبانی','field.logoRef':'مرجع لوگو','field.accent':'رنگ اصلی','field.locale':'زبان پیش‌فرض','field.customDomain':'دامنه اختصاصی','field.plan':'پلن Tenant','field.blueprintJson':'JSON مربوط به Blueprint','field.blueprintName':'نام Blueprint','field.releaseVersion':'نسخه انتشار','field.certificationLevel':'سطح تأیید فنی موردنیاز','field.description':'توضیحات','field.kubernetesMin':'حداقل Kubernetes','field.kubernetesMax':'حداکثر Kubernetes','field.architectures':'معماری‌ها','field.distributionProfiles':'هویت‌های توزیع','field.repository':'نشانی مخزن','field.ociRegistry':'رجیستری OCI','field.revisionType':'نوع بازنگری','field.revision':'بازنگری','field.evidenceRetention':'مدت نگهداری شواهد (روز)','field.tenantPlans':'پلن‌های مجاز Tenant','field.upgradeFrom':'نسخه‌های مبدأ ارتقا','field.leftRelease':'انتشار سمت چپ','field.rightRelease':'انتشار سمت راست',
  'help.machineName':'فقط حروف کوچک، عدد و خط تیره.','help.nodes':'تعداد دقیق بر اساس پروفایل انتخابی کنترل می‌شود.','help.noSecret':'فقط مرجع اطلاعات دسترسی را وارد کنید؛ رمز، کلید یا توکن را اینجا وارد نکنید.','help.multiSelect':'برای انتخاب چند مورد از Ctrl/Command استفاده کنید.',
  'platforms.startHeading':'ایجاد یا اتصال پلتفرم','platforms.startHelp':'هدف خود را انتخاب کنید؛ جزئیات فنی فقط در همان مسیر نمایش داده می‌شوند.','platforms.importTitle':'اتصال کلاستر موجود','platforms.importHelp':'یک کلاستر Kubernetes یا OKD موجود را با اعتبار کوتاه‌عمر متصل کنید.','platforms.importAction':'شروع اتصال ←','platforms.providerTitle':'ساخت از پروفایل زیرساخت','platforms.providerHelp':'یک مقصد اختصاصی RKE2/Kubernetes را از پروفایل زیرساخت تأییدشده بسازید.','platforms.providerAction':'بازکردن پروفایل‌های زیرساخت ←','platforms.okdTitle':'نصب مدیریت‌شده OKD Compact-3','platforms.okdHelp':'سه سرور فیزیکی با Redfish و فایل‌های نصب دقیق و تأییدشده؛ تأیید اجرا همیشه مستقل است.','platforms.okdAction':'پیکربندی نصب مدیریت‌شده ←','platforms.okdSummary':'مسیر پیشرفته سرور فیزیکی: فایل‌های نصب دقیق + سه BMC → تأیید مستقل → عملیات نصب ماندگار و قابل پیگیری.','managedOkd.heading':'درخواست نصب مدیریت‌شده OKD','managedOkd.help':'این فرم فقط مرجع اطلاعات دسترسی را ذخیره می‌کند و رمز BMC، کلید SSH یا kubeconfig نمی‌پذیرد.','managedOkd.identity':'هویت پلتفرم و شبکه','managedOkd.identityHelp':'پروژه مالک و هویت بیرونی کلاستر را مشخص کنید. VIP مربوط به API و Ingress باید متفاوت باشند.','managedOkd.version':'نسخه انتشار مربوط به OKD','managedOkd.clusterName':'نام کلاستر','managedOkd.baseDomain':'دامنه پایه','managedOkd.apiVip':'VIP مربوط به API','managedOkd.ingressVip':'VIP مربوط به Ingress','managedOkd.hardware':'سه سرور فیزیکی','managedOkd.hardwareHelp':'نشانی HTTPS مربوط به Redfish و مسیر دقیق System/VirtualMedia هر BMC را وارد کنید. فقط شناسه مرجع دسترسی را وارد کنید، نه رمز یا کلید واقعی.','managedOkd.hardwareTipTitle':'نکته:','managedOkd.hardwareTip':'اگر هر سه BMC مسیر Redfish یکسان دارند، ابتدا نود ۱ را کامل کنید و فقط همان مسیرها را کپی کنید؛ نشانی BMC و مرجع دسترسی کپی نمی‌شوند.','managedOkd.copyPaths':'کپی مسیرهای Redfish نود ۱','managedOkd.artifacts':'فایل‌های تأییدشده نصب','managedOkd.artifactsHelp':'نشانی HTTPS معتبر و SHA-256 دقیق را وارد کنید. درخواست مهر و قفل می‌شود و تا تأیید یک کاربر مجاز دیگر در انتظار می‌ماند.','managedOkd.reviewTitle':'پیش از ثبت','managedOkd.review1':'ثبت درخواست یک عملیات بحرانی ماندگار و قابل پیگیری می‌سازد و به معنی موفق‌شدن نصب نیست.','managedOkd.review2':'تأیید باید توسط کاربر مجاز دیگری انجام شود.','managedOkd.review3':'پیشرفت و شواهد مهرشده در بخش عملیات قابل پیگیری است.','managedOkd.submit':'ایجاد درخواست نصب نیازمند تأیید','managedOkd.runtimeChecking':'در حال بررسی آمادگی اجرای نصب مدیریت‌شده…','managedOkd.runtimeReady':'اجرای نصب آماده است. درخواست پس از تأیید مستقل وارد صف اجرا می‌شود.','managedOkd.runtimeUnavailable':'اجرای نصب مدیریت‌شده روی این کنترل‌پلین فعال نیست. ابتدا تنظیمات محیط اجرا و فضای کاری دقیق را تکمیل کنید؛ ثبت درخواست از پنل غیرفعال است.','managedOkd.connected':'متصل به اینترنت/منابع بالادستی','managedOkd.disconnected':'بدون دسترسی عمومی','managedOkd.connectivityHelp':'در حالت بدون دسترسی عمومی فقط بستهٔ آرشیوی مهرشدهٔ محلی oc-mirror v2 و رجیستری مدیریت‌شدهٔ محصول استفاده می‌شوند.','managedOkd.mirrorRegistry':'رجیستری داخلی مقصد','managedOkd.imageSetSha':'SHA-256 مربوط به ImageSetConfiguration','managedOkd.inventorySha':'SHA-256 مربوط به فهرست آینه','managedOkd.disconnectedTruth':'بدون بازگشت خودکار به رجیستری عمومی:','managedOkd.disconnectedTruthHelp':'درخواست فقط وقتی پذیرفته می‌شود که محیط اجرای دقیق oc-mirror v2 و بستهٔ آرشیوی محلی مهرشده آماده باشند.','managedOkd.runtimeDisconnectedUnavailable':'اجرای متصل آماده است، اما مسیر بدون دسترسی عمومی هنوز محیط اجرای دقیق oc-mirror v2 را ندارد.','action.continue':'ادامه','action.back':'بازگشت','providers.identityHelp':'روش تأمین زیرساخت و نوع توزیع دو مفهوم جدا هستند: رابط زیرساخت منابع را می‌سازد و Kubernetes یا RKE2 محیط اجرای مقصد را مشخص می‌کند.',
  'installation.heading':'نصب کنترل‌پلین Platform Factory','installation.description':'این صفحه فقط برای نصب و بازیابی کنترل‌پلین Platform Factory است. برای ساخت یا اتصال کلاسترهای مقصد از بخش «پلتفرم‌ها» استفاده کنید.','installation.profile':'پروفایل استقرار','installation.hosts':'سرورها و دسترسی','installation.network':'نشانی سرویس و TLS','installation.backup':'محل نسخهٔ پشتیبان خارج از نود','installation.acceptRisk':'هشدارها و ریسک‌های این نصب را بررسی کرده‌ام و در صورت نیاز آن‌ها را می‌پذیرم.','installation.planResult':'برنامه تأییدشده',
  'clusters.heading':'پلتفرم‌های Kubernetes','clusters.description':'یک پلتفرم مدیریت‌شده بسازید یا کلاستر موجود را متصل کنید؛ سپس وضعیت، قابلیت‌ها و عملیات آن را از یک مرجع معتبر دنبال کنید.','clusters.newImport':'اتصال کلاستر','clusters.newImportHelp':'اگر درخواست اتصال در زمان تعیین‌شده استفاده نشود، خودکار منقضی می‌شود.','clusters.enrollment':'فایل اتصال','clusters.connected':'کلاسترهای متصل','clusters.connectedHelp':'تازگی، وضعیت ثبت‌شده و Capability از Agent واقعی کلاستر می‌آید.','clusters.imports':'درخواست‌های اتصال','clusters.importsHelp':'هر درخواست را مستقل تأیید یا بررسی کنید.',
  'providers.heading':'پروفایل‌های زیرساخت','providers.description':'قابلیت زیرساخت را یک‌بار تأیید کنید و سپس پلتفرم اختصاصی Kubernetes/RKE2 را با مسیر دارای تأیید مستقل بسازید.','providers.profile':'تأیید پروفایل زیرساخت','providers.profileHelp':'فقط ClusterClassهای موجود و ازپیش‌مجاز قابل استفاده هستند.','providers.cluster':'ایجاد کلاستر اختصاصی','providers.clusterHelp':'ساخت تا زمان بررسی مشخصات دقیق توسط تأییدکننده در انتظار می‌ماند.','providers.profiles':'پروفایل‌های زیرساخت','providers.profilesHelp':'نتیجهٔ تأیید و اقدام‌های مجاز.','providers.clusters':'کلاسترهای اختصاصی','providers.clustersHelp':'ایجاد، تأیید، افزایش ظرفیت، ارتقا، تلاش دوباره و حذف را از همان رکورد مدیریت کنید.','providers.infrastructureHelp':'VMware را فقط وقتی انتخاب کنید که ClusterClass تأییدشده از الگوهای CAPV استفاده کند.','providers.vmwareEndpointHelp':'فقط نشانی اصلی HTTPS؛ نام کاربری، رمز عبور، مسیر یا توکن وارد نکنید.','providers.vmwareCredentialHelp':'فقط مرجع ExternalSecret موجود را وارد کنید؛ اطلاعات ورود vCenter در این فرم ثبت نمی‌شود.','providers.infrastructureExternal':'خارجی / نامشخص','providers.infrastructureVMware':'VMware vSphere',
  'marketplace.heading':'کاتالوگ آمادهٔ استفاده','marketplace.description':'فقط بسته‌های منتشرشده‌ای که مسیر نصب کامل و تأییدشده دارند قابل استقرار هستند. پیشنهادهای مشورتی به‌تنهایی تغییری ایجاد نمی‌کنند.','marketplace.offers':'بسته‌های منتشرشده','marketplace.offersHelp':'فقط بسته‌هایی نمایش داده می‌شوند که مسیر اجرایی معتبر دارند.','marketplace.installations':'نصب‌ها','marketplace.installationsHelp':'برنامه، تأیید، تلاش دوباره و حذف نصب را از همان رکورد مدیریت کنید.','marketplace.recommendations':'سابقه پیشنهادها','marketplace.recommendationsHelp':'نتایج مشورتی ذخیره‌شده، همراه با هشِ زمینه و پاسخ.',
  'baselines.heading':'استقرار Baseline تأییدشده','baselines.description':'بر اساس وضعیت واقعی کلاستر برنامه بسازید، تغییرات را پیش از اجرا مرور و تأیید کنید و فقط منابع مجاز را اعمال یا بازگردانی کنید.','baselines.history':'سابقه استقرار','baselines.historyHelp':'هر رکورد فقط اقدام‌هایی را نشان می‌دهد که در وضعیت فعلی واقعاً مجاز هستند.',
  'verification.heading':'بررسی سلامت و شواهد اجرا','verification.description':'بررسی سلامت نسخه‌قفل‌شده را اجرا کنید، نتیجهٔ هر بررسی را ببینید، خطاهای موقت را دوباره امتحان کنید و شواهد موفق را در یک فرایند قابل‌ادامه ثبت کنید.','verification.run':'اجرای بررسی سلامت','verification.runHelp':'پس از موفق‌شدن استقرار Baseline قابل اجرا می‌شود.','verification.closure':'ایجاد دور تکمیل','verification.closureHelp':'مراجع کنترل موجود را بدون دورزدن تأیید هماهنگ می‌کند.','verification.reports':'گزارش‌های اجرای واقعی','verification.reportsHelp':'نتیجهٔ واقعی Agent شامل بررسی، هش، خطا و تلاش دوباره است.','verification.campaigns':'دورهای تکمیل','verification.campaignsHelp':'هر بار یک وضعیت پایدار جلو می‌رود و پس از خطا از همان اقدام اصلی ادامه پیدا می‌کند.','verification.verifiedTitle':'شواهد تأییدشدهٔ تکمیل','verification.verifiedMessage':'اعتبارسنجی مستقل Digest موفق بود.','verification.integrityOnly':'این بررسی فقط یکپارچگی شواهد را تأیید می‌کند؛ تأیید محیط اجرا، تأیید HA و آمادگی تولید هنوز اثبات نشده‌اند.',
  'fleet.health':'سلامت ناوگان و پشتیبانی فنی','fleet.healthHelp':'تازگی اطلاعات کلاستر، آمادگی نودها، ذخیره‌سازی، ظرفیت، شبکه، گواهی‌ها و وضعیت پشتیبانی نسخهٔ Kubernetes را بررسی کنید.','fleet.supportBundle':'بسته پشتیبانی','fleet.supportBundleHelp':'بستهٔ تشخیصی پروژه را با حذف اطلاعات حساس دریافت کنید و در صورت نیاز با platformctl به‌صورت آفلاین صحت آن را بررسی کنید.','fleet.heading':'ناوگان','fleet.description':'کلاسترها را گروه‌بندی کنید، مغایرت واقعی را ببینید و نسخهٔ پایهٔ تأییدشده را به‌صورت آزمایشی و موج‌به‌موج منتشر کنید.','fleet.create':'ایجاد گروه ناوگان','fleet.createHelp':'کلاسترهای یک پروژه و سیاست عملیاتی مشترک را انتخاب کنید.','fleet.groups':'گروه‌های ناوگان','fleet.groupsHelp':'بررسی مغایرت یا ارتقا را از همان گروه شروع کنید.','fleet.scans':'بررسی‌های مغایرت','fleet.scansHelp':'مقایسهٔ زندهٔ وضعیت مطلوب و مشاهده‌شده برای هر کلاستر.','fleet.campaigns':'کارزارهای ارتقا','fleet.campaignsHelp':'تأیید، مرحلهٔ آزمایشی، موج اجرا و وضعیت توقف قابل مشاهده می‌ماند.',
  'tenants.heading':'Tenantها و برندینگ','tenants.description':'مجوز تجاری را اعمال، برندسازی سازمان را تنظیم و Namespace Tenantها را از طریق Agent مدیریت کنید.','tenants.entitlement':'مجوز تجاری','tenants.entitlementHelp':'نوع مجوز، تعداد Tenantها و امکانات برندینگ را تعیین می‌کند.','tenants.oem':'تنظیمات برند','tenants.oemHelp':'تنظیمات برند از سازمان انتخاب‌شده خوانده و در همان سازمان ذخیره می‌شود.','tenants.create':'ایجاد Namespace Tenant','tenants.createHelp':'فقط برنامه‌های مجاز کاتالوگ Tenant قابل انتخاب‌اند.','tenants.environments':'محیط‌های Tenant','tenants.environmentsHelp':'تعلیق، ادامه، تلاش دوباره و حذف فقط در وضعیت معتبر نمایش داده می‌شوند.',
  'blueprints.heading':'چرخه عمر نسخه‌های Blueprint','blueprints.description':'استاندارد نسخه‌دار پلتفرم را تعریف کنید، بازنگری‌های تغییرناپذیر را بررسی کنید، نسخهٔ تأییدشده را منتشر کنید و مسیر ارتقا را روشن نگه دارید.','blueprints.author':'ساخت و ویرایش پیش‌نویس','blueprints.authorHelp':'هر ذخیره یک بازنگری تغییرناپذیر تازه می‌سازد. محتوای منتشرشده درجا ویرایش نمی‌شود.','blueprints.compatibility':'سازگاری','blueprints.delivery':'تحویل GitOps','blueprints.tenancy':'Tenant و Evidence','blueprints.components':'اجزای پلتفرم','blueprints.componentsHelp':'اجزای اجباری همراه محصول روشن و قفل هستند؛ اجزای اختیاری انتخاب صریح اپراتور باقی می‌مانند.','blueprints.upgrades':'مبداهای پشتیبانی‌شده ارتقا','blueprints.upgradesHelp':'فقط انتشارهای همان پروژه و همان خانواده Blueprint مجاز هستند.','blueprints.lifecycle':'چرخه عمر','blueprints.lifecycleHelp':'پس از ورود به بازبینی تغییر محتوا متوقف می‌شود. انتشار خارج از local development به مدیر جداگانه نیاز دارد.','blueprints.compare':'مقایسه انتشارها','blueprints.compareHelp':'محتوای تغییرناپذیر ذخیره‌شده را پیش از تعریف مسیر ارتقای بعدی مقایسه کنید.','blueprints.releases':'انتشارهای Blueprint','blueprints.releasesHelp':'فقط نسخه‌های معتبر ذخیره‌شده نمایش داده می‌شوند و هیچ رکورد نمونه یا ساختگی به پنل افزوده نمی‌شود.','operations.heading':'فعالیت و ممیزی','operations.description':'وضعیت، مرحله، شواهد و سابقهٔ فقط‌افزودنی اقدامات را بررسی کنید.','operations.queueCenter':'مرکز صف عملیات','operations.queueCenterHelp':'فشار عملیات پایدار، تحویل اعلان و صف خروجی تراکنشی را بدون نمایش کنترل‌های اجراکنندهٔ داخلی بررسی کنید.','operations.logCenter':'مرکز لاگ محصول','operations.logCenterHelp':'ردیابی اجرای عملیات مجاز، رویدادهای ممیزی و اعلان‌های اخیر را جست‌وجو کنید. محتوای شواهد و اطلاعات محرمانه در این فهرست نمایش داده نمی‌شود.','operations.logSource':'منبع','operations.logLevel':'سطح','operations.logOperation':'عملیات','operations.logSearch':'جست‌وجو در پنجره بارگذاری‌شده','operations.searchLogs':'جست‌وجوی لاگ','operations.recent':'عملیات اخیر','operations.recentHelp':'رکورد را باز کنید تا مراحل و شواهد مهرشده را ببینید.','operations.audit':'رد ممیزی','operations.auditHelp':'آخرین اقدام‌های هر منبع همراه با اجراکننده و شمارهٔ بازنگری.','operations.targetLogs':'لاگ زندهٔ بارکاری مقصد','operations.targetLogsHelp':'از Agent متصل، نمای لحظه‌ای محدود QUERY/TAIL برای بارکاری موجود در وضعیت ثبت‌شده بگیرید. نتیجه به‌صورت شواهد مهرشده به یک عملیات فقط‌خواندنی متصل می‌شود.','operations.targetProject':'پروژه','operations.targetCluster':'کلاستر','operations.targetWorkload':'بارکاری','operations.targetContainer':'کانتینر اختیاری','operations.targetMode':'حالت','operations.targetSince':'بازه زمانی','operations.targetLimit':'حداکثر خطوط','operations.targetRun':'دریافت لاگ مقصد','services.heading':'یکپارچه‌سازی و سرویس‌ها','services.description':'وضعیت واقعی یکپارچه‌سازی Git، رجیستری، هویت و همگام‌سازی داخلی.','catalog.heading':'انتشارهای کاتالوگ','catalog.description':'محدودیت نسخه، سطح خطر، موج تحویل و وضعیت تأیید فنی از کاتالوگ همراه محصول.','validator.heading':'ابزارهای برنامه‌ریزی Blueprint','validator.description':'این رابط فقط برای برنامه‌ریزی است؛ منبعی را اعمال نمی‌کند و مرجع پنهان نمی‌سازد.','validator.warning':'این ابزار فقط نتیجهٔ برنامه‌ریزی می‌دهد. برای جریان اجرایی کلاستر از Marketplace یا Baseline Deployment استفاده کنید.','validator.result':'نتیجه Plan'
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
  localizeDynamicTree(document.body);
  localizeDynamicAttributes(document.body);
  updateBreadcrumb();
}

const faDynamic = {
  "Edge & sovereign": "لبه و حاکمیت محلی",
  "Bounded offline authority · evidence first": "اختیار محدود در حالت قطع ارتباط · شواهد در اولویت",
  "Prepare and review site-local authority without creating a second control plane. These tools compile policy, assess offline requests, verify boot evidence and validate disconnected AI profiles; they do not execute runtime mutations.": "اختیار محلی سایت را بدون ایجاد کنترل‌پلین دوم آماده و بررسی کنید. این ابزارها سیاست را تدوین می‌کنند، درخواست‌های زمان قطع ارتباط را می‌سنجند، شواهد راه‌اندازی را بررسی می‌کنند و پروفایل هوش مصنوعی آفلاین را اعتبارسنجی می‌کنند؛ هیچ تغییری در محیط اجرا انجام نمی‌دهند.",
  "Central authority remains canonical.": "مرجع مرکزی همچنان مرجع اصلی است.",
  "A site may act only inside an exact revision/digest policy and bounded offline window. Reconnect drift requires explicit review; physical certification is never inferred here.": "سایت فقط در محدودهٔ سیاستی با بازنگری و شناسهٔ یکپارچگی دقیق و بازهٔ قطع ارتباط محدود مجاز به اقدام است. اختلاف هنگام اتصال مجدد باید صریحاً بررسی شود و گواهی فیزیکی هرگز از این صفحه استنتاج نمی‌شود.",
  "All assessments are bound to one project. The global project scope, when selected, is enforced automatically.": "همهٔ ارزیابی‌ها به یک پروژه مقید هستند. اگر محدودهٔ سراسری پروژه انتخاب شده باشد، همان محدوده به‌صورت خودکار اعمال می‌شود.",
  "1. Compile site-local policy": "۱. تدوین سیاست محلی سایت",
  "Create a deterministic policy digest over central revision, desired state, admitted actions, offline window and evidence queue bounds.": "یک شناسهٔ یکپارچگی قطعی از بازنگری مرکزی، وضعیت مطلوب، اقدام‌های مجاز، بازهٔ قطع ارتباط و حد صف شواهد بسازید.",
  "Site ID": "شناسهٔ سایت",
  "Central revision": "بازنگری مرکزی",
  "Desired-state SHA-256": "SHA-256 وضعیت مطلوب",
  "Maximum offline seconds": "حداکثر زمان قطع ارتباط بر حسب ثانیه",
  "Maximum queued evidence": "حداکثر شواهد در صف",
  "Policy valid until": "اعتبار سیاست تا",
  "Admitted local actions": "اقدام‌های محلی مجاز",
  "Observe": "مشاهده",
  "Collect diagnostics": "جمع‌آوری اطلاعات تشخیصی",
  "Restart approved workload": "راه‌اندازی مجدد بارکاری تأییدشده",
  "Cordon node": "جلوگیری از زمان‌بندی روی نود",
  "Uncordon node": "بازکردن زمان‌بندی روی نود",
  "Reconcile approved desired state": "همگام‌سازی وضعیت مطلوب تأییدشده",
  "Compile policy": "تدوین سیاست",
  "2. Assess offline mutation": "۲. ارزیابی تغییر در حالت قطع ارتباط",
  "Assessment only. A positive result means the request fits the sealed policy; execution still requires the normal durable operation and agent path.": "فقط ارزیابی انجام می‌شود. نتیجهٔ مثبت یعنی درخواست با سیاست مهرشده سازگار است؛ اجرا همچنان باید از مسیر معمول عملیات پایدار و Agent انجام شود.",
  "Target reference": "مرجع مقصد",
  "Idempotency key": "کلید عدم‌تکرار",
  "Request SHA-256": "SHA-256 درخواست",
  "Disconnected since": "زمان آغاز قطع ارتباط",
  "Assess request": "ارزیابی درخواست",
  "3. Review reconnect conflict": "۳. بررسی تعارض هنگام اتصال مجدد",
  "Compare the last assessed offline request with authoritative central revision/digest. Central drift is never silently overwritten.": "آخرین درخواست ارزیابی‌شده در حالت قطع ارتباط را با بازنگری و شناسهٔ یکپارچگی معتبر مرکزی مقایسه کنید. اختلاف با وضعیت مرکزی هرگز بی‌صدا بازنویسی نمی‌شود.",
  "Current central revision": "بازنگری فعلی مرکزی",
  "Current desired-state SHA-256": "SHA-256 فعلی وضعیت مطلوب",
  "Review reconnect": "بررسی اتصال مجدد",
  "4. Assess boot security": "۴. ارزیابی امنیت راه‌اندازی",
  "Verify the submitted attestation claim requires TPM, Secure Boot, measured boot, disk encryption, quote verification, nonce binding and PCR policy match.": "بررسی کنید ادعای گواهی‌شده شامل TPM، Secure Boot، راه‌اندازی اندازه‌گیری‌شده، رمزگذاری دیسک، تأیید Quote، اتصال Nonce و تطبیق سیاست PCR باشد.",
  "Quote SHA-256": "SHA-256 Quote",
  "Event log SHA-256": "SHA-256 گزارش رویداد",
  "Evidence SHA-256": "SHA-256 شواهد",
  "TPM present": "TPM موجود است",
  "Secure Boot enabled": "Secure Boot فعال است",
  "Measured boot present": "شواهد راه‌اندازی اندازه‌گیری‌شده موجود است",
  "Disk encryption verified": "رمزگذاری دیسک تأیید شده است",
  "Quote verified": "Quote تأیید شده است",
  "Nonce bound": "Nonce به درخواست متصل است",
  "PCR policy matched": "سیاست PCR تطبیق دارد",
  "Assess boot evidence": "ارزیابی شواهد راه‌اندازی",
  "5. Validate disconnected local AI": "۵. اعتبارسنجی هوش مصنوعی محلی در حالت قطع ارتباط",
  "Validate an exact model/runtime profile for zero-egress local inference. This does not start a model server and never permits external provider credentials.": "یک پروفایل دقیق مدل و محیط اجرا را برای استنتاج محلی بدون ارتباط خروجی اعتبارسنجی کنید. این کار سرور مدل را اجرا نمی‌کند و هرگز اطلاعات دسترسی ارائه‌دهندهٔ خارجی را مجاز نمی‌کند.",
  "Runtime": "محیط اجرا",
  "Model SHA-256": "SHA-256 مدل",
  "Runtime image SHA-256": "SHA-256 ایمیج محیط اجرا",
  "Maximum prompt bytes": "حداکثر بایت ورودی",
  "Maximum output bytes": "حداکثر بایت خروجی",
  "Network egress, raw credentials and external providers are fixed to disabled by this profile.": "در این پروفایل، ارتباط خروجی شبکه، اطلاعات دسترسی خام و ارائه‌دهندهٔ خارجی همیشه غیرفعال هستند.",
  "Validate local AI profile": "اعتبارسنجی پروفایل هوش مصنوعی محلی",
  "4 · Application delivery composition": "۴ · ترکیب تحویل برنامه",
  "Compose reusable application shapes, capabilities, managed dependencies and environment promotion without turning target objects into product authority.": "الگوی برنامه، قابلیت‌ها، وابستگی‌های مدیریت‌شده و ارتقای محیط را به‌صورت قابل‌استفادهٔ مجدد ترکیب کنید، بدون اینکه منابع مقصد به مرجع اصلی محصول تبدیل شوند.",
  "Authority boundary:": "مرز مرجع:",
  "releases are immutable. Environment bindings are revisioned promotion pointers fenced to the exact active Workspace namespace binding. A capability already owned by the target is suppressed instead of installing a duplicate stack.": "نسخه‌های انتشار تغییرناپذیرند. اتصال محیط، اشاره‌گر نسخه‌دار ارتقا است و به اتصال فعال و دقیق Namespace در Workspace مقید می‌ماند. اگر مقصد از قبل مالک یک قابلیت باشد، همان قابلیت سرکوب می‌شود تا Stack تکراری نصب نشود.",
  "Workload shapes": "الگوهای اجرای برنامه",
  "Capability traits": "قابلیت‌های ترکیبی",
  "Managed dependencies": "وابستگی‌های مدیریت‌شده",
  "Environment bindings": "اتصال‌های محیط",
  "Preview target capability resolution": "پیش‌نمایش تطبیق قابلیت‌های مقصد",
  "Read-only: determine which traits apply and which are suppressed because the target already owns that capability.": "فقط خواندنی: مشخص کنید کدام قابلیت‌های ترکیبی اعمال می‌شوند و کدام مورد به‌دلیل وجود همان قابلیت در مقصد کنار گذاشته می‌شود.",
  "Workload shape": "الگوی اجرای برنامه",
  "Capabilities already provided by target": "قابلیت‌های موجود در مقصد",
  "networking.ingress, monitoring.metrics": "networking.ingress، monitoring.metrics",
  "Comma-separated canonical capability IDs from target discovery. This preview does not mutate target runtime.": "شناسه‌های استاندارد قابلیت را که از شناسایی مقصد به‌دست آمده‌اند با ویرگول جدا کنید. این پیش‌نمایش Runtime مقصد را تغییر نمی‌دهد.",
  "Preview resolution": "پیش‌نمایش تطبیق",
  "Promote an environment binding": "ارتقای نسخه در یک محیط",
  "Advance one exact environment binding to another immutable release. Scope cannot move during promotion.": "یک اتصال دقیق محیط را به نسخهٔ انتشار تغییرناپذیر دیگری ارتقا دهید. محدودهٔ محیط هنگام ارتقا قابل جابه‌جایی نیست.",
  "Environment binding": "اتصال محیط",
  "Immutable release": "نسخهٔ انتشار تغییرناپذیر",
  "Observed native capabilities": "قابلیت‌های بومی مشاهده‌شده",
  "Review & promote release": "بررسی و ارتقای نسخه",
  "Workload shapes & capabilities": "الگوهای برنامه و قابلیت‌ها",
  "Workspace profiles & immutable releases": "پروفایل‌های Workspace و نسخه‌های تغییرناپذیر",
  "Environment promotion bindings": "اتصال‌های ارتقای محیط",
  "Create virtual cluster desired state": "ایجاد وضعیت مطلوب کلاستر مجازی",
  "Bind a bounded developer or team profile to one active Workspace namespace reference. Runtime execution remains independently gated until a virtual-cluster executor is admitted.": "یک پروفایل محدود توسعه‌دهنده یا تیم را به یک مرجع Namespace فعال در Workspace متصل کنید. اجرای Runtime تا پذیرش مجری کلاستر مجازی به‌صورت مستقل مسدود می‌ماند.",
  "Virtual cluster request": "درخواست کلاستر مجازی",
  "The request stores workspace-bound desired state only. REQUESTED is not Running or Ready.": "این درخواست فقط وضعیت مطلوب متصل به Workspace را ذخیره می‌کند. REQUESTED به معنی Running یا Ready نیست.",
  "Active namespace binding": "اتصال فعال Namespace",
  "Developer · auto-sleep": "توسعه‌دهنده · خواب خودکار",
  "Team · larger quota": "تیم · سهمیه بیشتر",
  "CPU · millicores": "CPU · میلی‌هسته",
  "Memory · MiB": "حافظه · MiB",
  "Storage · GiB": "فضای ذخیره‌سازی · GiB",
  "Maximum namespaces": "حداکثر Namespace",
  "Auto-sleep after · minutes": "خواب خودکار پس از · دقیقه",
  "Developer profile requires 15–1440 minutes. Team profile may use 0 to disable auto-sleep.": "پروفایل توسعه‌دهنده به ۱۵ تا ۱۴۴۰ دقیقه نیاز دارد. در پروفایل تیم می‌توان مقدار ۰ را برای غیرفعال‌کردن خواب خودکار انتخاب کرد.",
  "Source/API authority is available. Runtime executor and runtime certification are still pending; this action does not imply that a virtual cluster is running.": "مرجع Source/API در دسترس است. مجری Runtime و گواهی Runtime هنوز در انتظارند؛ این عملیات به معنی در حال اجرا بودن کلاستر مجازی نیست.",
  "Create desired state": "ایجاد وضعیت مطلوب",
  "Virtual cluster desired state": "وضعیت مطلوب کلاستر مجازی",
  "Workspace-bound requests and lifecycle truth. REQUESTED remains pending until the runtime executor is admitted.": "درخواست‌های متصل به Workspace و حقیقت چرخه‌عمر. وضعیت REQUESTED تا پذیرش مجری Runtime در انتظار می‌ماند.",
  "No active namespace binding": "اتصال فعال Namespace وجود ندارد",
  "Desired state is durable; runtime execution is not yet certified.": "وضعیت مطلوب ماندگار است؛ اجرای Runtime هنوز گواهی نشده است.",
  "Lifecycle state is authoritative; runtime certification remains independent.": "وضعیت چرخه‌عمر مرجع است؛ گواهی Runtime مستقل باقی می‌ماند.",
  "Inspect desired state": "بررسی وضعیت مطلوب",
  "No virtual cluster requests": "درخواست کلاستر مجازی وجود ندارد",
  "Create a bounded desired-state request from an active namespace binding.": "از یک اتصال فعال Namespace، درخواست وضعیت مطلوب محدود ایجاد کنید.",
  "Virtual cluster request already exists with the same idempotency key.": "درخواست کلاستر مجازی با همین کلید idempotency از قبل وجود دارد.",
  "Virtual cluster desired state recorded; runtime execution remains pending.": "وضعیت مطلوب کلاستر مجازی ثبت شد؛ اجرای Runtime همچنان در انتظار است.",
  "This record is product desired-state authority. Runtime executor and runtime certification remain independent.": "این رکورد مرجع وضعیت مطلوب محصول است. مجری Runtime و گواهی Runtime مستقل باقی می‌مانند.",
  "External / unspecified": "خارجی / نامشخص",
  "VMware vSphere": "VMware vSphere (وی‌اسفیر)",
  "Microsoft Azure": "Microsoft Azure (آژور)",
  "Google Cloud": "Google Cloud (گوگل کلاد)",
  "Managed providers are admitted only when the selected ClusterClass is backed by the matching CAPV/CAPA/CAPZ/CAPG templates.": "ارائه‌دهندهٔ مدیریت‌شده فقط زمانی پذیرفته می‌شود که ClusterClass انتخاب‌شده به Template متناظر CAPV، CAPA، CAPZ یا CAPG متصل باشد.",
  "Required only for VMware. AWS, Azure and GCP use their canonical provider API authority; custom cloud endpoints are not admitted.": "این نشانی فقط برای VMware لازم است. AWS، Azure و GCP از مرجع رسمی API خود استفاده می‌کنند و Endpoint سفارشی برای Cloud پذیرفته نمی‌شود.",
  "Reference an existing ExternalSecret in 4so-provider-system. Raw cloud or vCenter credentials are never entered here.": "یک ExternalSecret موجود در Namespace سامانهٔ ارائه‌دهنده را ارجاع دهید. اطلاعات دسترسی خام Cloud یا vCenter هرگز در این فرم وارد نمی‌شود.",
  "FinOps & chargeback": "مدیریت هزینه و مصرف",
  "Measured usage · versioned rates": "مصرف اندازه‌گیری‌شده · نرخ‌های نسخه‌دار",
  "Review measured infrastructure usage and derive showback or chargeback from an immutable rate card. Missing telemetry is always shown as unavailable, never as zero cost.": "مصرف اندازه‌گیری‌شده زیرساخت را بررسی کنید و هزینه را فقط از نرخ‌های نسخه‌دار و تغییرناپذیر محاسبه کنید. دادهٔ اندازه‌گیری‌نشده همیشه ناموجود نشان داده می‌شود و هرگز صفر فرض نمی‌شود.",
  "Collector-owned telemetry.": "دادهٔ مصرف فقط از جمع‌آورندهٔ مورد اعتماد می‌آید.",
  "Operators can publish rate cards here, but usage observations come only from trusted collectors. AI and the browser cannot submit billing telemetry.": "اپراتور می‌تواند نرخ‌ها را اینجا منتشر کند، اما دادهٔ مصرف فقط از جمع‌آورنده‌های مورد اعتماد پذیرفته می‌شود. هوش مصنوعی و مرورگر اجازهٔ ثبت دادهٔ مالی اندازه‌گیری‌شده را ندارند.",
  "Publish a rate card": "انتشار نرخ هزینه",
  "Create an immutable, organization-scoped price version. Existing observations are never rewritten.": "یک نسخهٔ تغییرناپذیر از نرخ‌ها برای این سازمان بسازید. داده‌های مصرف قبلی بازنویسی نمی‌شوند.",
  "New rate card": "نرخ هزینهٔ جدید",
  "Prices use integer micro-currency per unit to avoid floating-point billing drift.": "نرخ‌ها به‌صورت عدد صحیح در واحد یک‌میلیونم پول ثبت می‌شوند تا خطای اعشاری وارد محاسبات مالی نشود.",
  "Rate card name": "نام نرخ هزینه",
  "Currency": "واحد پول",
  "Effective at": "زمان شروع اعتبار",
  "CPU core-hour · micros": "هزینه هر Core-hour پردازنده · یک‌میلیونم",
  "Memory GiB-hour · micros": "هزینه هر GiB-hour حافظه · یک‌میلیونم",
  "Storage GiB-hour · micros": "هزینه هر GiB-hour فضای ذخیره‌سازی · یک‌میلیونم",
  "Accelerator device-hour · micros": "هزینه هر ساعت شتاب‌دهنده · یک‌میلیونم",
  "Publish immutable rate card": "انتشار نرخ تغییرناپذیر",
  "Rate cards": "نرخ‌های هزینه",
  "Versioned pricing authority for the selected organization.": "نسخه‌های معتبر نرخ هزینه برای سازمان انتخاب‌شده.",
  "Measured usage": "مصرف اندازه‌گیری‌شده",
  "Collector observations and explicit telemetry gaps. A gap makes authoritative total cost unavailable.": "داده‌های ثبت‌شدهٔ جمع‌آورنده و کمبودهای صریح اندازه‌گیری. اگر داده‌ای کم باشد، هزینهٔ نهایی معتبر نمایش داده نمی‌شود.",
  "Chargeback rows": "ریز هزینه‌ها",
  "Deterministic projection from measured usage plus the selected immutable rate card. Incomplete rows stay visibly incomplete.": "ریز هزینه از مصرف اندازه‌گیری‌شده و نرخ معتبر محاسبه می‌شود. ردیف ناقص همیشه به‌صورت ناقص باقی می‌ماند و صفر فرض نمی‌شود.",
  "Export CSV": "دریافت CSV",
  "Delivery adapter contracts": "قراردادهای تحویل اعلان",
  "Provider capabilities come from backend authority. Raw credential material is never part of the browser contract.": "قابلیت‌های ارائه‌دهنده از مرجع سمت سرور خوانده می‌شوند. اطلاعات محرمانهٔ دسترسی هرگز وارد قرارداد مرورگر نمی‌شود.",
  "External registry admission": "بررسی پذیرش رجیستری خارجی",
  "Validate a digest-pinned external OCI reference against the current organization/project scope. This is a read-only admission preview; zot remains the managed registry authority.": "مرجع OCI خارجی با digest ثابت را در محدودهٔ سازمان و پروژه بررسی کنید. این فقط پیش‌نمایش خواندنی پذیرش است و zot همچنان مرجع رجیستری مدیریت‌شده می‌ماند.",
  "Registry URL": "نشانی رجیستری",
  "Direction": "جهت انتقال",
  "Import": "ورود",
  "Mirror": "همگام‌سازی",
  "Export": "خروج",
  "Exact image reference": "مرجع دقیق ایمیج",
  "Credential reference": "مرجع اطلاعات دسترسی",
  "Reference only; never enter a token, password, or registry URL with userinfo.": "فقط مرجع اطلاعات دسترسی را وارد کنید؛ توکن، رمز عبور یا نشانی رجیستری دارای نام کاربری را وارد نکنید.",
  "Preview admission": "بررسی پذیرش",
  "No registry is configured or mutated.": "هیچ رجیستری پیکربندی یا تغییر داده نمی‌شود.",
  "Select a global organization/project scope and validate an exact external image reference.": "محدودهٔ سازمان یا پروژه را انتخاب کنید و مرجع دقیق ایمیج خارجی را بررسی کنید.",
  "EXTERNAL EGRESS": "ارتباط خروجی خارجی",
  "LOCAL": "محلی",
  "Authorization": "احراز مجوز",
  "supported": "پشتیبانی می‌شود",
  "not used": "استفاده نمی‌شود",
  "Durable delivery": "تحویل پایدار",
  "Retry / dead letter": "تلاش مجدد / تحویل ناموفق",
  "Raw secret material": "اطلاعات محرمانهٔ خام",
  "ALLOWED": "مجاز",
  "forbidden": "ممنوع",
  "Provider contracts unavailable": "قراردادهای ارائه‌دهنده در دسترس نیست",
  "Notification adapter authority was not returned by the API.": "مرجع آداپتور اعلان از API دریافت نشد.",
  "Policy digest": "شناسهٔ یکپارچگی سیاست",
  "Notification route": "مسیر اعلان",
  "Event patterns": "الگوهای رویداد",
  "Revision": "بازنگری",
  "Unavailable": "در دسترس نیست",
  "Select an organization or project in the global scope first.": "ابتدا سازمان یا پروژه را در محدودهٔ سراسری انتخاب کنید.",
  "Decision": "تصمیم",
  "Registry": "رجیستری",
  "Digest": "شناسهٔ یکپارچگی",
  "Managed registry authority": "مرجع رجیستری مدیریت‌شده",
  "Mutable tags": "تگ‌های تغییرپذیر",
  "Raw credentials": "اطلاعات دسترسی خام",
  "allowed": "مجاز",
  "yes": "بله",
  "no": "خیر",
  "External registry reference admitted for planning.": "مرجع رجیستری خارجی برای برنامه‌ریزی پذیرفته شد.",
  "AI control coverage": "پوشش کنترل هوش مصنوعی",
  "Durable AI control jobs": "عملیات پایدار کنترل هوش مصنوعی",
  "Every AI-triggered mutation is idempotent and recorded before the canonical product action runs. Retry replays a terminal result and never blindly re-dispatches an indeterminate mutation.": "هر تغییر درخواستی هوش مصنوعی پیش از اجرای اقدام اصلی به‌صورت پایدار و تکرارایمن ثبت می‌شود. تلاش دوباره همان نتیجهٔ نهایی ثبت‌شده را برمی‌گرداند و تغییر را کورکورانه دوباره اجرا نمی‌کند.",
  "Live MCP/API parity from the router authority. Protected credential, worker-internal and raw-payload routes remain intentionally unavailable to AI.": "پوشش زنده MCP و API مستقیماً از مرجع مسیریابی محصول خوانده می‌شود. مسیرهای اطلاعات دسترسی، اجزای اجرایی داخلی و دادهٔ خام عمداً در اختیار هوش مصنوعی قرار نمی‌گیرند.",
  "Refresh": "به‌روزرسانی",
  "Agent ISO": "ایمیج ISO مربوط به Agent",
  "Application workspaces": "فضاهای کاری اپلیکیشن",
  "Artifact version": "نسخه فایل نصب",
  "Control-plane install": "نصب کنترل‌پلین",
  "Create & manage platforms": "ایجاد و مدیریت پلتفرم",
  "Create a short-lived enrollment only when onboarding an existing target.": "فقط هنگام اتصال یک کلاستر موجود، درخواست کوتاه‌عمر ایجاد کنید.",
  "HTTPS URL": "نشانی HTTPS",
  "Infrastructure profiles": "پروفایل‌های زیرساخت",
  "Marketplace": "مارکت‌پلیس",
  "Node 1": "نود ۱",
  "Node 2": "نود ۲",
  "Node 3": "نود ۳",
  "Node ID": "شناسه نود",
  "Redfish endpoint": "نشانی Redfish",
  "Release payload": "بسته Release",
  "START HERE": "از اینجا شروع کنید",
  "STEP 1 / 3": "مرحله ۱ از ۳",
  "STEP 2 / 3": "مرحله ۲ از ۳",
  "STEP 3 / 3": "مرحله ۳ از ۳",
  "System resource": "مسیر System",
  "VirtualMedia resource": "مسیر VirtualMedia",
  "Data protection": "پشتیبان‌گیری و بازیابی",
  "Schedule evidence-backed backups and run isolated restore drills before disruptive work.": "پشتیبان‌گیری‌های زمان‌بندی‌شده را با شواهد قابل‌بررسی اجرا کنید و پیش از تغییرات حساس، بازیابی آزمایشی را در محیط ایزوله بسنجید.",
  "Backup policy": "سیاست پشتیبان‌گیری",
  "Create a project-scoped Velero policy. Only an opaque credential reference is stored; secret material never enters the control plane.": "یک سیاست Velero در محدوده همین پروژه تعریف کنید. فقط مرجع اطلاعات دسترسی ذخیره می‌شود و رمز، کلید یا توکن هرگز وارد کنترل‌پلین نمی‌شود.",
  "Policy name": "نام سیاست",
  "Backup storage location": "محل ذخیره نسخه پشتیبان",
  "Reference only. Do not paste a password, key or token.": "فقط مرجع را وارد کنید؛ رمز، کلید یا توکن را اینجا وارد نکنید.",
  "UTC schedule": "زمان‌بندی UTC",
  "Protected namespaces": "Namespaceهای تحت حفاظت",
  "Comma-separated namespaces. Restore Drill V1 requires a policy with exactly one namespace.": "نام Namespaceها را با ویرگول جدا کنید. در نسخه فعلی، بازیابی آزمایشی فقط برای سیاستی با یک Namespace انجام می‌شود.",
  "Create backup policy": "ایجاد سیاست پشتیبان‌گیری",
  "Backup and restore runs": "اجرای پشتیبان‌گیری و بازیابی",
  "Backups and restore drills run as durable fenced Agent jobs. Direct restore requires a different approver from the requester.": "پشتیبان‌گیری و بازیابی آزمایشی به‌صورت Job پایدار و کنترل‌شده توسط Agent اجرا می‌شوند. بازیابی مستقیم باید توسط فردی غیر از درخواست‌دهنده تأیید شود.",
  "payments,orders": "payments,orders",
  "Target node lifecycle readiness": "وضعیت عملیات نود",
  "Preview node Add, Drain, Remove, Replace, OS Patch, Certificate Renewal and Remediation against the latest inventory. Actions without a real executor remain explicitly blocked.": "پیش از هر تغییر، امکان افزودن، تخلیه، حذف، جایگزینی، به‌روزرسانی سیستم‌عامل، تمدید گواهی و بازیابی نود را بر اساس آخرین وضعیت کلاستر بررسی کنید. هر عملیاتی که اجرای واقعی ندارد غیرفعال می‌ماند.",
  "No node lifecycle authority": "اطلاعات لازم برای عملیات نود در دسترس نیست",
  "Connect a cluster with current inventory first.": "ابتدا یک کلاستر با اطلاعات به‌روز متصل کنید.",
  "Current inventory cannot provide node lifecycle planning authority.": "اطلاعات فعلی کلاستر برای برنامه‌ریزی عملیات نود کافی نیست.",
  "Required capabilities": "قابلیت‌های لازم",
  "Missing capabilities": "قابلیت‌های در دسترس نیست",
  "Development blockers": "کارهای توسعه‌ای باقی‌مانده",
  "Physical certification": "تأیید در محیط واقعی",
  "Preview impact": "بررسی اثر تغییر",
  "Bind provider": "زیرساخت متصل",
  "Request Add": "درخواست افزودن",
  "Request Remove": "درخواست حذف",
  "Request Replace": "درخواست جایگزینی",
  "Request provider-backed node Remove": "درخواست حذف نود",
  "Request provider-backed node Replace": "درخواست جایگزینی نود",
  "Ready worker node": "نود Worker آماده‌به‌کار",
  "Active maintenance window": "پنجره نگه‌داری باز",
  "No active maintenance window is available for destructive node lifecycle execution.": "هیچ پنجره نگه‌داری بازی برای اجرای مخرب چرخه عمر نود موجود نیست.",
  "No Ready worker-only node is available for provider lifecycle execution.": "هیچ نود Worker-only آماده‌ای برای اجرای چرخه عمر زیرساخت موجود نیست.",
  "Node Remove requested and waiting for independent provider approval.": "درخواست حذف نود ثبت شد و برای تأیید مسئول مستقل ارسال شد.",
  "Node Replace requested and waiting for independent provider approval.": "درخواست جایگزینی نود ثبت شد و برای تأیید مسئول مستقل ارسال شد.",
  "Existing provider node lifecycle request reused.": "همین درخواست قبلاً ثبت شده است؛ همان درخواست موجود ادامه داده می‌شود.",
  "Provider binding": "زیرساخت متصل",
  "Not bound": "هنوز متصل نشده",
  "No ACTIVE provider cluster is available for this target project.": "برای این پروژه زیرساخت فعالی برای مدیریت نودها پیدا نشد.",
  "Bind target to provider cluster": "اتصال کلاستر به زیرساخت مدیریتی",
  "Provider cluster": "کلاستر زیرساخت",
  "Bind provider cluster": "اتصال کلاستر زیرساخت",
  "Provider binding saved.": "زیرساخت متصل ذخیره شد.",
  "Request provider-backed node Add": "درخواست افزودن نود",
  "Node Add requested and waiting for independent provider approval.": "درخواست افزودن نود ثبت شد و برای تأیید مسئول مستقل ارسال شد.",
  "Existing node Add request reused.": "همین درخواست افزودن قبلاً ثبت شده است؛ همان درخواست موجود ادامه داده می‌شود.",
  "Current inventory has no nodes for lifecycle planning.": "اطلاعات فعلی کلاستر هیچ نودی برای برنامه‌ریزی این عملیات ندارد.",
  "Preview node lifecycle impact": "بررسی اثر تغییر چرخه عمر نود",
  "وضعیت ثبت‌شده node": "نود ثبت‌شده",
  "Target node lifecycle plan": "برنامه عملیات نود",
  "Authority": "مرجع",
  "Action": "اقدام",
  "اجراکننده": "اجراکننده",
  "Node": "نود",
  "وضعیت ثبت‌شده": "وضعیت ثبت‌شده",
  "Plan digest": "شناسهٔ یکپارچگی برنامه",
  "Impact": "اثر",
  "Recovery": "بازیابی",
  "EXECUTABLE": "قابل اجرا",
  "BLOCKED": "مسدود",
  "Search console destinations": "جست‌وجوی مقصدهای پنل",
  "Navigate only — mutations remain inside their authoritative workflow.": "این جست‌وجو فقط شما را به بخش موردنظر می‌برد؛ انجام تغییرات فقط از مسیر تأییدشدهٔ همان بخش ممکن است.",
  "Search console": "جست‌وجوی پنل",
  "Refresh current page": "بازخوانی صفحه جاری",
  "Next action": "اقدام بعدی",
  "Review next action": "بررسی اقدام بعدی",
  "Loading scope…": "در حال بارگذاری محدوده…",
  "Checking session…": "در حال بررسی نشست…",
  "Loading…": "در حال بارگذاری…",
  "Confirm action": "تأیید اقدام",
  "All product logs": "همه لاگ‌های محصول",
  "Operation traces": "جزئیات اجرای عملیات",
  "Audit actions": "رویدادهای ممیزی",
  "Notification events": "رویدادهای اعلان",
  "All levels": "همه سطح‌ها",
  "Error": "خطا",
  "Warning": "هشدار",
  "Info": "اطلاعات",
  "Debug": "دیباگ",
  "All operations": "همه عملیات",
  "Search logs": "جست‌وجوی لاگ",
  "Create an organization": "ایجاد سازمان",
  "Organizations": "سازمان‌ها",
  "Connected clusters": "کلاسترهای متصل",
  "Successful baselines": "استقرارهای موفق Baseline",
  "Needs attention": "نیازمند توجه",
  "No failed product workflow": "هیچ فرایند ناموفقی ثبت نشده است",
  "Create a project": "ایجاد پروژه",
  "Connect a Kubernetes cluster": "اتصال کلاستر Kubernetes",
  "Apply the certified baseline": "استقرار Baseline تأییدشده",
  "Verify runtime health": "بررسی سلامت سرویس‌ها",
  "Close runtime evidence": "تکمیل شواهد تأیید",
  "No urgent action": "اقدام فوری وجود ندارد",
  "No activity yet": "هنوز فعالیتی ثبت نشده است",
  "Create an organization and start the first workflow.": "ابتدا یک سازمان بسازید و سپس اولین کار را شروع کنید.",
  "1. Organization": "۱. سازمان",
  "2. Project": "۲. پروژه",
  "3. Connect infrastructure": "۳. اتصال زیرساخت",
  "No organization selected": "سازمانی انتخاب نشده است",
  "Select an organization to review access.": "برای بررسی دسترسی یک سازمان انتخاب کنید.",
  "OIDC group mapping authority": "تنظیم دسترسی گروه‌های OIDC",
  "Map identity-provider groups to product and optional organization/project roles. Realm roles are not authoritative.": "گروه‌های سامانهٔ هویت را به نقش‌های محصول و در صورت نیاز به سازمان یا پروژه متصل کنید. نقش‌های Realm به‌تنهایی مجوز دسترسی به محصول نیستند.",
  "OIDC group": "گروه OIDC",
  "Product role": "نقش محصول",
  "Organization scope": "محدوده سازمان",
  "Organization role": "نقش سازمان",
  "Project scope": "محدوده پروژه",
  "Project role": "نقش پروژه",
  "Create mapping": "ایجاد نگاشت",
  "No OIDC group mappings": "نگاشت گروه OIDC وجود ندارد",
  "Create an explicit group mapping before relying on OIDC identities for product access.": "پیش از استفاده از ورود سازمانی، مشخص کنید هر گروه OIDC چه دسترسی‌ای در محصول دارد.",
  "No accessible organization": "سازمان قابل دسترسی وجود ندارد",
  "A platform administrator must create an organization or grant membership.": "مدیر پلتفرم باید سازمان ایجاد کند یا عضویت بدهد.",
  "Infrastructure region": "Region زیرساخت",
  "Platform service integrations": "یکپارچه‌سازی سرویس‌های پلتفرم",
  "Managed services are the safe default. External modes expose only adapter-supported fields and accept secret references instead of plaintext credentials.": "سرویس‌های مدیریت‌شده انتخاب پیشنهادی و امن هستند. در حالت خارجی فقط تنظیمات موردنیاز همان اتصال نمایش داده می‌شود و رمز یا کلید خام وارد پنل نمی‌شود.",
  "Git desired state": "وضعیت مطلوب Git",
  "Mode and provider": "حالت و Provider",
  "PostgreSQL authority": "مرجع PostgreSQL",
  "Evidence and backup storage": "ذخیره شواهد و نسخه‌های پشتیبان",
  "Identity and SSO": "ورود سازمانی و مدیریت هویت",
  "A project is required before a cluster can be connected.": "پیش از اتصال کلاستر باید پروژه ایجاد شود.",
  "Create organization and project": "ایجاد سازمان و پروژه",
  "No connected clusters": "کلاستر متصلی وجود ندارد",
  "Create and approve an enrollment request, then apply its manifest on the target cluster.": "یک درخواست اتصال ایجاد و تأیید کنید، سپس فایل اتصال را روی کلاستر مقصد اعمال کنید.",
  "Cluster environment & maintenance": "محیط کلاستر و نگه‌داری",
  "Define the cluster environment, open a bounded maintenance window and run disruption-aware node maintenance through the connected agent.": "نوع محیط کلاستر را مشخص کنید، یک بازهٔ زمانی محدود برای نگه‌داری باز کنید و عملیات نود را از طریق Agent متصل و با کنترل اثر سرویس انجام دهید.",
  "Cluster": "کلاستر",
  "Environment": "محیط",
  "Default drain timeout (seconds)": "مهلت پیش‌فرض تخلیه نود (ثانیه)",
  "Save environment profile": "ذخیره پروفایل محیط",
  "Window name": "نام پنجره",
  "Starts": "شروع",
  "Ends": "پایان",
  "Max unavailable": "حداکثر خارج از دسترس",
  "Drain timeout (seconds)": "مهلت تخلیه نود (ثانیه)",
  "Create maintenance window": "ایجاد پنجره نگه‌داری",
  "Maintenance windows": "پنجره‌های نگه‌داری",
  "Maintenance runs": "اجراهای نگه‌داری",
  "No maintenance windows": "پنجره نگه‌داری وجود ندارد",
  "No maintenance runs": "اجرای نگه‌داری وجود ندارد",
  "No enrollment requests": "درخواست Enrollment وجود ندارد",
  "A project and connected management cluster are required before provider verification.": "پیش از تأیید Provider، پروژه و کلاستر مدیریت متصل لازم است.",
  "Connect a cluster": "اتصال کلاستر",
  "ClusterClass": "کلاس کلاستر (ClusterClass)",
  "Architecture": "معماری",
  "Distribution": "توزیع",
  "A project is required before a Blueprint release can be authored.": "پیش از ایجاد Blueprint Release باید پروژه وجود داشته باشد.",
  "Visual / API authoring parity": "هم‌ارزی ویرایشگر بصری و API",
  "The visual editor is bound to the same strict Blueprint schema used by the API. Import, export and verify an exact canonical round-trip before saving a release.": "ویرایشگر تصویری از همان Schema رسمی Blueprint در API استفاده می‌کند. پیش از ذخیرهٔ نسخه، واردکردن، خروجی‌گرفتن و بازخوانی مجدد را بررسی کنید تا داده بدون تغییر رفت‌وبرگشت کند.",
  "Export visual JSON": "خروجی JSON بصری",
  "Import JSON into visual editor": "ورود JSON به ویرایشگر بصری",
  "Verify API round-trip": "تأیید Round-trip API",
  "Canonical Blueprint JSON": "JSON استاندارد Blueprint",
  "Overlay & field ownership": "Overlay و مالکیت فیلد",
  "Create immutable provider/environment overlays. Paths without an explicit ownership rule remain Blueprint-only and cannot be overridden.": "برای زیرساخت یا محیط، Overlay تغییرناپذیر بسازید. هر مسیری که مالکیت آن صریحاً واگذار نشده باشد فقط در اختیار Blueprint می‌ماند و قابل بازنویسی نیست.",
  "Overlay scope": "محدوده Overlay",
  "Overlay name": "نام Overlay",
  "Version": "نسخه",
  "Scope key": "کلید Scope",
  "Changes": "تغییرات",
  "Create immutable overlay": "ایجاد لایهٔ تنظیمات تغییرناپذیر",
  "No overlays": "Overlay وجود ندارد",
  "Create a provider or environment overlay when a Blueprint explicitly delegates fields.": "وقتی Blueprint فیلدی را صریحاً واگذار می‌کند، لایهٔ تنظیمات زیرساخت یا محیط را ایجاد کنید.",
  "Catalog release": "Release کاتالوگ",
  "API version": "نسخه API",
  "Kind": "نوع",
  "Source release": "Release مبدا",
  "Provider overlay": "Overlay مربوط به Provider",
  "Environment overlay": "Overlay مربوط به Environment",
  "Field ownership policy": "سیاست مالکیت فیلد",
  "Rules": "قواعد",
  "Resolve preview": "پیش‌نمایش نتیجهٔ حل تنظیمات",
  "Governance": "حاکمیت",
  "Admin": "مدیریت",
  "Blueprints": "Blueprintها",
  "Certification profile details": "جزئیات پروفایل Certification",
  "Runtime certification": "Certification زمان اجرا",
  "Certification runs": "اجراهای Certification",
  "Fresh-install namespace": "Namespace نصب تازه",
  "Queue certification run": "صف اجرای Certification",
  "Compatibility check": "بررسی سازگاری",
  "Evaluate compatibility": "ارزیابی سازگاری",
  "Authentication & authorization audit": "ممیزی احراز هویت و مجوزدهی",
  "Immutable hash-chained security decisions for authentication, product RBAC and organization/project scope authorization.": "تصمیم‌های امنیتی تغییرناپذیر و زنجیره‌شده با هش برای احراز هویت، RBAC محصول و مجوزدهی در محدودهٔ سازمان/پروژه.",
  "رد ممیزی": "ردپای ممیزی",
  "Audit events": "رویدادهای ممیزی",
  "Notifications & action routing": "اعلان‌ها و مسیریابی اقدام",
  "Destinations": "مقصدها",
  "Create destination": "ایجاد مقصد",
  "Create routing rule": "ایجاد قانون مسیریابی",
  "Delivery history": "تاریخچه تحویل",
  "Dead letters": "Dead Letterها",
  "Event history": "تاریخچه رویداد",
  "Event types": "نوع رویدادها",
  "Create credential reference": "ایجاد Credential Reference",
  "Ensure desired-state repository": "اطمینان از Repository مربوط به Desired State",
  "Publish signed desired-state revision": "انتشار Revision امضاشده Desired State",
  "Git organization": "سازمان گیت",
  "Repository": "مخزن (Repository)",
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
  "Create immutable candidate": "ایجاد گزینهٔ انتشار تغییرناپذیر",
  "Components included in this release": "اجزای این Release",
  "Active trust keys": "کلیدهای اعتماد فعال",
  "Catalog digest": "Digest کاتالوگ",
  "Catalog name": "نام Catalog",
  "Initial channel:": "Channel اولیه:",
  "Credential rotation / revocation": "Rotation / Revocation مربوط به Credential",
  "Credential state": "وضعیت Credential",
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
  "No provider profiles": "پروفایل زیرساخت وجود ندارد",
  "Connect a Cluster API management cluster and verify its admitted ClusterClass.": "یک کلاستر مدیریت Cluster API متصل و ClusterClass پذیرفته‌شده آن را تأیید کنید.",
  "No dedicated clusters": "کلاستر اختصاصی وجود ندارد",
  "Verify a provider profile and create the first approval-bound cluster request.": "یک پروفایل زیرساخت را تأیید و اولین درخواست کلاستر Approval-bound را ایجاد کنید.",
  "No published offers": "بسته منتشرشده‌ای وجود ندارد",
  "An offer is hidden until its complete runtime workflow is admitted.": "Offer تا زمان پذیرفته‌شدن Workflow کامل Runtime نمایش داده نمی‌شود.",
  "No marketplace installations": "نصب Marketplace وجود ندارد",
  "Select an offer and connected cluster to create the first plan.": "یک Offer و کلاستر متصل انتخاب کنید تا اولین Plan ساخته شود.",
  "No recommendations": "پیشنهادی وجود ندارد",
  "Enter a concrete objective to request an advisory-only recommendation.": "یک هدف مشخص وارد کنید تا پیشنهاد مشورتی دریافت شود.",
  "No baseline deployments": "استقرار Baseline تأییدشده وجود ندارد",
  "Connect a cluster and create the first live plan.": "یک کلاستر متصل و اولین Plan واقعی را ایجاد کنید.",
  "No runtime verification": "تأیید Runtime وجود ندارد",
  "Apply a baseline successfully, then run the digest-pinned probe.": "Baseline را با موفقیت اعمال کنید و سپس Probe قفل‌شده به هش را اجرا کنید.",
  "No closure campaigns": "دور تکمیلی وجود ندارد",
  "Select a baseline deployment and create the first resumable campaign.": "یک استقرار Baseline تأییدشده انتخاب و اولین Campaign قابل Resume را ایجاد کنید.",
  "No fleet groups": "Fleet Group وجود ندارد",
  "Select connected clusters and create the first fleet group.": "کلاسترهای متصل را انتخاب و اولین Fleet Group را ایجاد کنید.",
  "No drift scans": "Drift Scan وجود ندارد",
  "Run a live read-only drift scan from a fleet group.": "یک بررسی زنده و فقط‌خواندنی از مغایرت‌های گروه ناوگان اجرا کنید.",
  "No upgrade campaigns": "Upgrade Campaign وجود ندارد",
  "Create an upgrade campaign from an eligible fleet group.": "از گروه ناوگان واجد شرایط یک کارزار ارتقا بسازید.",
  "No tenant environments": "محیط Tenant وجود ندارد",
  "Apply an entitlement and create the first namespace tenant.": "Entitlement را اعمال و اولین Namespace Tenant را ایجاد کنید.",
  "No durable operations": "عملیات پایدار وجود ندارد",
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
  "Approve apply": "تأیید اعمال",
  "Approve install": "تأیید نصب",
  "Approve campaign": "تأیید Campaign",
  "Advance campaign": "پیشبرد Campaign",
  "Advance one step": "یک مرحله پیشروی",
  "Retry failed step": "تلاش مجدد مرحله ناموفق",
  "Retry verification": "تلاش مجدد تأیید",
  "Verify evidence": "اعتبارسنجی Evidence",
  "Verified closure evidence": "شواهد تأییدشدهٔ تکمیل",
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
  "Read-only session": "نشست فقط خواندنی",
  "Skip to main content": "پرش به محتوای اصلی",
  "Git delivery & last-known-good authority": "مرجع تحویل Git و آخرین نسخه سالم",
  "Review pending signed pull requests, merge only approved revisions, and inspect the last revision proven healthy by sync observation. Rollback writes the sealed LKG content back to the managed branch and requires a new sync observation.": "درخواست‌های تغییر امضاشده را بررسی کنید، فقط نسخه‌های تأییدشده را ادغام کنید و آخرین نسخه‌ای را که همگام‌سازی موفق آن ثابت شده ببینید. بازگشت، آخرین نسخهٔ سالم را به شاخهٔ مدیریت‌شده برمی‌گرداند و پس از آن باید همگام‌سازی جدید دوباره تأیید شود.",
  "Pull requests": "Pull Requestها",
  "Last-known-good revisions": "آخرین Revisionهای سالم",
  "Git provider & credential authority": "مرجع Git Provider و Credential",
  "Connect Forgejo from the console using durable credential references. Secret material stays in the referenced runtime secret source and is never persisted by Platform Factory.": "Forgejo را با مرجع امن اطلاعات دسترسی متصل کنید. مقدار محرمانه در محل امن اجرای سرویس باقی می‌ماند و Platform Factory آن را ذخیره نمی‌کند.",
  "Provider setup & credentials": "راه‌اندازی Provider و Credentialها",
  "Connect or rotate Forgejo only when configuration changes": "Forgejo را فقط هنگام تغییر پیکربندی متصل یا Rotate کنید",
  "Repository & publishing actions": "Repository و عملیات انتشار",
  "Execution authority": "مرجع اجرای عملیات",
  "Lease owner": "مالک Lease",
  "Lease expiry": "انقضای Lease",
  "Fence": "Fence",
  "Operation executor": "اجراکننده عملیات",
  // CONSOLE_FULL_LOCALIZATION_V1 — reviewed static and accessibility-copy closure.
  "0 components": "۰ مؤلفه",
  "1 hour": "۱ ساعت",
  "1 · Non-HA": "۱ · بدون HA",
  "1 · Variable schema": "۱ · Schema متغیرها",
  "1. Create credential reference": "۱. ایجاد مرجع اطلاعات دسترسی",
  "15 minutes": "۱۵ دقیقه",
  "2 · Operating policy set": "۲ · مجموعه سیاست عملیاتی",
  "2. Connect Forgejo provider": "۲. زیرساخت متصل مربوط به Forgejo",
  "3 · Certified Platform Template": "۳ · Certified Platform Template",
  "3 · HA": "۳ · HA",
  "30 minutes": "۳۰ دقیقه",
  "4 hours": "۴ ساعت",
  "5 minutes": "۵ دقیقه",
  "60 minutes": "۶۰ دقیقه",
  "A Workspace stores product ownership and exact cluster/namespace bindings. Runtime state remains authoritative on the referenced cluster and is loaded only by downstream read surfaces.": "فضای کاری مالکیت محصول و اتصال‌های دقیق کلاستر/Namespace را نگه می‌دارد. وضعیت واقعی زمان اجرا همچنان روی کلاستر مرجع است و فقط از مسیرهای خواندنی پایین‌دستی بارگذاری می‌شود.",
  "A template is configuration authority, not runtime truth. Adoption remains blocked until target inventory, disruptive impact and certification evidence are evaluated immediately before execution.": "Template مرجع پیکربندی است، نه حقیقت Runtime. پذیرش تا زمانی مسدود می‌ماند که وضعیت ثبت‌شده مقصد، اثر اختلال و شواهد Certification بلافاصله پیش از اجرا ارزیابی شوند.",
  "AI / Agent Access Center": "مرکز دسترسی AI / Agent",
  "AI Control Plane": "Control Plane هوش مصنوعی",
  "AI Operator": "اپراتور AI",
  "AI cannot decide deterministic PASS or Exact-SHA Physical PASS.": "AI نمی‌تواند PASS قطعی یا Exact-SHA Physical PASS را تعیین کند.",
  "AI receives only bounded failure packets after deterministic failures. It cannot decide PASS or Physical PASS.": "هوش مصنوعی فقط پس از خطاهای قطعی، خلاصهٔ محدود و پاک‌سازی‌شدهٔ خطا را دریافت می‌کند و حق اعلام موفقیت تست یا آزمون فیزیکی را ندارد.",
  "API round-trip parity, canonical JSON and immutable overlay ownership": "هم‌ارزی رفت‌وبرگشت API، JSON مرجع و مالکیت تغییرناپذیر لایهٔ تنظیمات",
  "Acme Cloud": "ابر Acme",
  "Actionable events derived from the transactional outbox and fleet health scanner.": "رویدادهای قابل اقدام که از Transactional Outbox و اسکنر سلامت Fleet مشتق می‌شوند.",
  "Active and revoked cluster/namespace references for the selected Workspace.": "مراجع فعال و لغوشده کلاستر/Namespace برای Workspace انتخاب‌شده.",
  "Activity & audit": "فعالیت و ممیزی",
  "Add a mapping only when identity-provider group policy changes.": "فقط زمانی نگاشت اضافه کنید که سیاست گروه Identity Provider تغییر کرده باشد.",
  "Add explicit file paths and content; the backend records the declared immutable revision digest during publication.": "مسیر و محتوای فایل را صریح اضافه کنید؛ سرور هنگام انتشار، هش بازنگری تغییرناپذیر اعلام‌شده را ثبت می‌کند.",
  "All accessible projects": "همه پروژه‌های قابل دسترسی",
  "All projects in organization": "همه پروژه‌های سازمان",
  "Allow DNS": "اجازه DNS",
  "Allow plain HTTP for trusted internal/test network": "اجازه HTTP ساده برای شبکه داخلی/آزمایشی مورد اعتماد",
  "Allow plaintext secrets": "اجازهٔ ذخیره Secret به‌صورت متن ساده",
  "Allowed target classes": "کلاس‌های مقصد مجاز",
  "Approval required for risk": "نیازمند Approval بر اساس ریسک",
  "Approved release; content and upgrade contract are immutable.": "نسخه تأیید شده است؛ محتوا و قرارداد ارتقا تغییرناپذیرند.",
  "Assurance": "تضمین",
  "Budget limit · micros": "سقف بودجه · میکروواحد پولی",
  "Budget limits use integer micro-currency. Warning and critical thresholds are explicit and versioned; recommendations never auto-apply infrastructure changes.": "سقف‌های بودجه با میکروواحد پولیِ عدد صحیح محاسبه می‌شوند. آستانه‌های هشدار و بحرانی صریح و نسخه‌دارند؛ پیشنهادها هیچ تغییر زیرساختی را خودکار اعمال نمی‌کنند.",
  "Budget name": "نام بودجه",
  "Budget policies": "سیاست‌های بودجه",
  "Critical threshold · %": "آستانه بحرانی · ٪",
  "Evidence-backed review suggestions only. No recommendation changes infrastructure automatically.": "فقط پیشنهادهای بازبینی مبتنی بر شواهد نمایش داده می‌شوند. هیچ پیشنهادی زیرساخت را خودکار تغییر نمی‌دهد.",
  "Immutable guardrails for the selected scope. UNKNOWN means evidence is incomplete, not zero spend.": "قواعد تغییرناپذیر برای محدوده انتخاب‌شده. UNKNOWN یعنی شواهد کامل نیستند، نه اینکه هزینه صفر است.",
  "New budget policy": "سیاست بودجه جدید",
  "Organization total": "کل سازمان",
  "Publish an immutable budget policy for the selected organization/project. Forecasts remain unavailable when measured cost evidence is incomplete.": "برای سازمان/پروژه انتخاب‌شده یک سیاست بودجه تغییرناپذیر منتشر کنید. تا وقتی شواهد هزینه اندازه‌گیری‌شده کامل نباشد، پیش‌بینی نمایش داده نمی‌شود.",
  "Publish immutable budget": "انتشار بودجه تغییرناپذیر",
  "Rightsizing review": "بازبینی اندازه منابع (Rightsizing)",
  "Set a budget guardrail": "تعیین حد بودجه",
  "Warning threshold · %": "آستانه هشدار · ٪",
  "Attempts, HTTP result, retry state and dead letters are durable.": "تعداد تلاش‌ها، نتیجهٔ HTTP، وضعیت تلاش مجدد و پیام‌های تحویل‌نشده به‌صورت پایدار ثبت می‌شوند.",
  "Authenticated MCP exposes read-only product context by default and only allow-listed delegated operations when mcp.operate is explicitly granted.": "پس از ورود، MCP فقط اطلاعاتی را نشان می‌دهد که کاربر در محصول مجاز به دیدن آن است. انجام تغییر فقط با دسترسی صریح و از مسیر عملیات پشتیبانی‌شده ممکن است.",
  "Author and save immutable revisions.": "بازنگری‌های تغییرناپذیر را ایجاد و ذخیره کنید.",
  "Authoritative resource": "منبع مرجع",
  "Authorization env reference": "مرجع Environment برای Authorization",
  "Automatic acquisition is fail-closed through the lock shipped inside the exact release. The current production lock is incomplete, so provide a verified digest-locked bundle directory or the runner returns LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING before any network access.": "دریافت خودکار فقط با قفل همان نسخهٔ دقیق انجام می‌شود و در هر ابهام یا خطا متوقف می‌ماند. قفل فعلی برای Production کامل نیست؛ بنابراین یک پوشهٔ بستهٔ تأییدشده و قفل‌شده به هش ارائه کنید، وگرنه اجراکننده پیش از هر دسترسی شبکه‌ای LAB_CANONICAL_BUNDLE_SOURCE_LOCKS_PENDING را برمی‌گرداند.",
  "Autopilot Campaign Center": "مرکز Campaignهای Autopilot",
  "Back": "بازگشت",
  "Backup completed at": "Backup تکمیل‌شده در",
  "Backup provider": "Provider مربوط به Backup",
  "Backup reference": "مرجع Backup",
  "Backup required": "Backup الزامی است",
  "Backup schedule": "زمان‌بندی Backup",
  "Base URL": "نشانی پایه (URL)",
  "Basics": "مبانی",
  "Bind an existing managed cluster namespace. Cross-project cluster references fail closed.": "یک Namespace از کلاستر مدیریت‌شدهٔ موجود را متصل کنید. ارجاع بین‌پروژه‌ای ناسازگار به کلاستر رد می‌شود.",
  "Bind a bounded developer or team profile to one active Workspace namespace reference. Runtime lifecycle is executed only by the admitted exact-source virtual-cluster executor and remains independent from Physical certification.": "یک پروفایل محدود Developer یا Team را به مرجع Namespace فعال همین Workspace متصل کنید. چرخهٔ Runtime فقط توسط executor تأییدشده با source دقیق اجرا می‌شود و مستقل از Physical certification باقی می‌ماند.",
  "Bind namespace": "Bind کردن Namespace",
  "Bind reusable maintenance, backup and pod-security policy without making the template an execution engine.": "سیاست‌های نگه‌داری، نسخهٔ پشتیبان و امنیت Pod را به قالب اضافه کنید، بدون اینکه خود قالب به موتور اجرا تبدیل شود.",
  "Bind to a published signed catalog when controlled supply-chain governance is required.": "وقتی کنترل زنجیرهٔ تأمین لازم است، آن را به یک کاتالوگ منتشرشده و امضاشده متصل کنید.",
  "Blueprint authoring progress": "پیشرفت Authoring مربوط به Blueprint",
  "Bootstrap self-signed": "Bootstrap با گواهی Self-signed",
  "Branch": "شاخه",
  "Branch · planning only": "Branch · فقط برای Planning",
  "Cancel edit": "لغو ویرایش",
  "Catalog governance actions": "اقدامات حاکمیتی Catalog",
  "Catalog releases": "Catalog Releaseها",
  "Certification produced here is local control-plane/agent evidence. External Live Acceptance and Production Ready remain false until an external lab campaign is completed.": "تأییدی که اینجا ساخته می‌شود فقط شواهد محلی کنترل‌پلین و Agent است. پذیرش بیرونی و آمادگی Production تا زمانی که آزمون آزمایشگاهی مربوطه تکمیل نشود تأیید نمی‌شوند.",
  "Certification profile": "پروفایل Certification",
  "Certified baselines": "Baselineهای Certified",
  "Certified composition": "ترکیب Certified",
  "Checkpoint valid until": "Checkpoint معتبر تا",
  "Choose authoritative event types and one or more active destinations. Project scope is optional.": "نوع رویداد مرجع و یک یا چند مقصد فعال را انتخاب کنید. محدودهٔ پروژه اختیاری است.",
  "Choose event scope, type and severity to inspect matching rules and destinations.": "Scope، نوع و Severity رویداد را برای بررسی Ruleها و مقصدهای منطبق انتخاب کنید.",
  "Choose the ownership scope and immutable release identity before configuring runtime behavior.": "پیش از پیکربندی رفتار زمان اجرا، محدودهٔ مالکیت و هویت تغییرناپذیر نسخه را انتخاب کنید.",
  "Close": "بستن",
  "Close search": "بستن جست‌وجو",
  "Cluster API topology v1beta2": "Topology مربوط به Cluster API v1beta2",
  "Clusters": "کلاسترها",
  "Comma-separated canonical target classes. Admission still checks the selected target at use time.": "کلاس‌های مرجع مقصد را با ویرگول جدا کنید. بررسی پذیرش هنگام استفاده همچنان مقصد انتخاب‌شده را ارزیابی می‌کند.",
  "Commercial & branding settings": "تنظیمات تجاری و Branding",
  "Component catalog": "Catalog مؤلفه‌ها",
  "Compose exact immutable authorities. Only published, execution-ready Blueprint releases in the same project are eligible.": "مراجع دقیق و تغییرناپذیر را ترکیب کنید. فقط نسخه‌های منتشرشده و آمادهٔ اجرای Blueprint در همان پروژه مجازند.",
  "Compose immutable Blueprint releases, typed variables and reusable operating policy. Template admission is source-only until a real target impact preview and the required certification gates are satisfied.": "نسخه‌های تغییرناپذیر Blueprint، متغیرهای نوع‌دار و سیاست عملیاتی قابل استفادهٔ مجدد را ترکیب کنید. پذیرش قالب فقط در سطح سورس است تا زمانی که پیش‌نمایش واقعی اثر روی مقصد و گیت‌های لازم اعتبارسنجی برآورده شوند.",
  "Composition is immutable; target impact is deliberately not guessed here.": "ترکیب تغییرناپذیر است؛ اثر روی مقصد در این مرحله عمداً حدس زده نمی‌شود.",
  "Configure routing": "پیکربندی Routing",
  "Connect Forgejo": "اتصال Forgejo",
  "Connect cluster": "اتصال کلاستر",
  "Console destinations retain local delivery history. Webhooks require HTTPS unless explicit internal HTTP is enabled.": "مقصدهای Console تاریخچه Delivery محلی را نگه می‌دارند. Webhookها به HTTPS نیاز دارند مگر HTTP داخلی صریحاً فعال شده باشد.",
  "Console history": "تاریخچه Console",
  "Context type": "نوع Context",
  "Context-bound diagnosis and delegated product operations over authoritative platform state. AI diagnosis stays advisory and redacted; allow-listed MCP mutations require explicit operator scope and never receive PASS, Physical PASS, RBAC escalation or shell authority.": "هوش مصنوعی فقط با دادهٔ مجاز و محدود پلتفرم وضعیت را تحلیل می‌کند و می‌تواند تغییرات پشتیبانی‌شده را درخواست کند. نتیجهٔ تحلیل مشورتی است، اطلاعات حساس حذف می‌شوند و هیچ مدل یا اتصال MCP نمی‌تواند تأیید نهایی، دسترسی بیشتر، Shell یا گواهی اجرای فیزیکی را دور بزند.",
  "Create OIDC group mapping": "ایجاد نگاشت گروه OIDC",
  "Create a CANDIDATE release from the authoritative shipped inventory. Higher channels require resolved immutable supply-chain evidence.": "از موجودی رسمی همراه محصول یک نسخهٔ کاندید بسازید. انتشار در سطح‌های بالاتر فقط وقتی مجاز است که منبع و شواهد زنجیرهٔ تأمین دقیق و تغییرناپذیر باشند.",
  "Create a new deployment only after selecting the target and reviewing the certified baseline.": "فقط پس از انتخاب مقصد و بررسی Baseline تأییدشده یک Deployment جدید ایجاد کنید.",
  "Create a scoped expiring identity only for automation that needs API access.": "هویت دارای تاریخ انقضا و محدود به دامنهٔ مجاز را فقط برای خودکارسازی‌ای بسازید که به API دسترسی نیاز دارد.",
  "Create a scoped, server-verified and redacted support bundle for escalation or operator investigation.": "برای ارجاع یا بررسی اپراتور، بستهٔ پشتیبانی محدود و تأییدشده در سرور بسازید که اطلاعات حساس از آن حذف شده باشد.",
  "Create a short-lived enrollment only when onboarding a new target.": "Enrollment کوتاه‌عمر را فقط هنگام Onboarding یک مقصد جدید ایجاد کنید.",
  "Create an evidence-bound certification run from a published renderable Catalog release and fresh cluster inventory. FOUNDATION_V1 proves the executable foundation. OBSERVABILITY_V1 executes real Prometheus/VictoriaMetrics-compatible metrics queries, Loki push/query, and Alertmanager fire/query through cluster-agent adapters. TARGET_RUNTIME_V1 actively proves target-cluster DNS, default-deny NetworkPolicy behavior, same-tenant reachability, negative cross-tenant isolation with an explicit-allow positive control, PVC I/O, CSI VolumeSnapshot create/restore, Velero Backup/Restore, and the observability checks when the cluster agent discovers matching executable provider surfaces. It directly installs and certifies only the secure-namespace-foundation harness; other Catalog components require component-specific runtime certification authority before they may enter the RUNTIME channel. Missing or unavailable providers remain BLOCKED.": "از یک نسخهٔ منتشرشده و قابل اجرای کاتالوگ، همراه با وضعیت ثبت‌شدهٔ تازهٔ کلاستر، یک اجرای اعتبارسنجی متصل به شواهد بسازید. FOUNDATION_V1 پایهٔ اجرایی را اثبات می‌کند. OBSERVABILITY_V1 پرس‌وجوهای واقعی Metrics سازگار با Prometheus/VictoriaMetrics، مسیرهای Push/Query در Loki و Fire/Query در Alertmanager را از طریق Adapterهای Cluster Agent اجرا می‌کند. TARGET_RUNTIME_V1 به‌صورت فعال DNS مقصد، رفتار مسدودسازی پیش‌فرض NetworkPolicy، دسترسی درون همان Tenant، جداسازی بین Tenantها با کنترل مثبت صریح، I/O روی PVC، ایجاد و بازیابی CSI VolumeSnapshot، پشتیبان‌گیری و بازیابی با Velero و بررسی‌های Observability را زمانی اثبات می‌کند که Agent سطح اجرایی ارائه‌دهندهٔ لازم را کشف کرده باشد. این پروفایل فقط secure-namespace-foundation را مستقیماً نصب و اعتبارسنجی می‌کند؛ سایر مؤلفه‌های کاتالوگ پیش از ورود به کانال RUNTIME به مرجع اختصاصی اعتبارسنجی زمان اجرا نیاز دارند. اگر ارائه‌دهندهٔ لازم وجود نداشته باشد یا در دسترس نباشد، وضعیت BLOCKED باقی می‌ماند.",
  "Create automation identity": "ایجاد هویت Automation",
  "Create desired-state repositories or publish immutable signed revisions": "ایجاد مخزن‌های Desired State یا انتشار بازنگری‌های تغییرناپذیر امضاشده",
  "Create groups or change the trusted Git drift source only when fleet topology changes.": "فقط هنگام تغییر توپولوژی ناوگان، گروه ایجاد کنید یا منبع مورداعتماد Git برای تشخیص مغایرت را تغییر دهید.",
  "Create immutable policy set": "ایجاد مجموعه سیاست تغییرناپذیر",
  "Create immutable template": "ایجاد قالب تغییرناپذیر",
  "Create immutable variable schema": "ایجاد طرح متغیرهای تغییرناپذیر",
  "Create or edit destinations and routing only when delivery policy changes.": "مقصدها و Routing را فقط زمانی ایجاد یا ویرایش کنید که سیاست Delivery تغییر کرده باشد.",
  "Create organization or project": "ایجاد سازمان یا پروژه",
  "Create platform template": "ایجاد Platform Template",
  "Create policy set": "ایجاد Policy Set",
  "Create tenant": "ایجاد Tenant",
  "Create the stable project-scoped boundary first; add namespace bindings separately.": "ابتدا Boundary پایدار Project-scoped را بسازید؛ Bindingهای Namespace را جداگانه اضافه کنید.",
  "Create variable schema": "ایجاد Variable Schema",
  "Create workspace": "ایجاد Workspace",
  "Creates or verifies a private repository through the configured internal Git adapter.": "یک مخزن خصوصی را از طریق رابط داخلی Git ایجاد یا بررسی می‌کند.",
  "Credential": "اعتبارنامه",
  "Cross-cluster team boundary": "Boundary تیم Cross-cluster",
  "Customer A": "مشتری A",
  "DEPRECATED / REVOKED": "منسوخ / لغوشده",
  "Default deny egress": "Default deny برای Egress",
  "Default deny ingress": "Default deny برای Ingress",
  "Define supported Kubernetes targets, selected components and the Git/OCI delivery contract.": "مقصدهای Kubernetes پشتیبانی‌شده، مؤلفه‌های انتخابی و قرارداد Delivery مربوط به Git/OCI را تعریف کنید.",
  "Define typed operator inputs without storing resolved secret values in the template.": "ورودی‌های نوع‌دار اپراتور را بدون ذخیره مقدار حل‌شدهٔ Secret در قالب تعریف کنید.",
  "Deletion policy": "سیاست حذف",
  "Deploy certified baseline": "استقرار Baseline تأییدشده تأییدشده",
  "Deployment automation": "Automation استقرار",
  "Describe the intended platform standard and operator outcome": "استاندارد موردنظر Platform و نتیجه مورد انتظار Operator را توضیح دهید",
  "Describe the outcome you need": "نتیجه موردنیاز را توضیح دهید",
  "Development": "توسعه",
  "Diagnose authoritative context": "عیب‌یابی بر اساس زمینهٔ مرجع",
  "Diagnose with AI": "Diagnosis با AI",
  "Direct commit": "Commit مستقیم",
  "Disconnected / air-gap": "قطع‌اتصال / Air-gap",
  "Display name": "نام نمایشی",
  "Distribution identity": "هویت Distribution",
  "Do not paste passwords, API keys or private keys. Central redaction is still enforced before provider egress.": "رمز عبور، کلید API یا کلید خصوصی را اینجا وارد نکنید. پیش از ارسال هر داده به سرویس هوش مصنوعی، اطلاعات حساس به‌صورت مرکزی حذف می‌شود.",
  "Download a redacted project support bundle when troubleshooting or escalating an incident.": "برای عیب‌یابی یا ارجاع مشکل به پشتیبانی، بستهٔ تشخیصی پروژه را با حذف اطلاعات حساس دریافت کنید.",
  "Download project support bundle": "دانلود Support Bundle پروژه",
  "Download verified bundle": "دانلود Bundle تأییدشده",
  "Drift details": "جزئیات Drift",
  "Durable AI run history": "تاریخچه durable اجرای AI",
  "Durable INSTALL → VERIFY state with inventory/source-lock/render binding, checkpoint evidence, expiry and explicit BLOCKED/FAILED states.": "فرایند نصب تا بررسی نهایی به‌صورت قابل‌ادامه ثبت می‌شود و به وضعیت کلاستر، قفل منبع و خروجی Render متصل است. نقاط بازیابی، مهلت اعتبار و حالت‌های خطا نیز صریح نگه‌داری می‌شوند.",
  "Durable operation": "عملیات پایدار",
  "Edge Cluster 1": "کلاستر Edge ۱",
  "Enforce digest-pinned images": "الزام تصویرهای قفل‌شده به هش",
  "English": "انگلیسی",
  "Ensure repository": "اطمینان از Repository",
  "Enterprise · 100 tenants + OEM": "Enterprise · ۱۰۰ Tenant + OEM",
  "Entitlement and OEM presentation are administration settings, not daily tenant operations.": "Entitlement و نمایش OEM تنظیمات Administration هستند، نه عملیات روزمره Tenant.",
  "Environment reference only. Raw tokens are never accepted by this form.": "فقط مرجع Environment. Token خام هرگز توسط این Form پذیرفته نمی‌شود.",
  "Environment variable name only; never paste the token here.": "فقط نام متغیر محیطی را وارد کنید؛ توکن را اینجا قرار ندهید.",
  "Ephemeral runtime": "Runtime موقت",
  "Evaluate the current authoritative rules before changing routing or sending an event. Preview is read-only and creates no notification event or delivery.": "پیش از تغییر مسیر اعلان‌ها یا ارسال رویداد، قوانین فعلی را بررسی کنید. پیش‌نمایش فقط برای مشاهده است و هیچ اعلان یا ارسال واقعی ایجاد نمی‌کند.",
  "Evaluate the pasted Blueprint against one concrete Kubernetes target using the same server-side compatibility authority used by Provider lifecycle.": "Blueprint واردشده را برای یک مقصد مشخص Kubernetes با همان مرجع سازگاری سمت سرور که چرخهٔ عمر زیرساخت استفاده می‌کند ارزیابی کنید.",
  "Event type": "نوع رویداد",
  "Every line is an exact JSON Pointer and policy. Unlisted paths are BLUEPRINT_ONLY.": "هر خط یک JSON Pointer دقیق و Policy است. Pathهای فهرست‌نشده BLUEPRINT_ONLY هستند.",
  "Evidence digest": "Digest مربوط به Evidence",
  "Exact bundle authority": "Authority مربوط به Bundle دقیق",
  "Exact event types or prefix patterns are evaluated with organization/project and severity scope.": "نوع رویداد یا الگوی پیشوند آن بر اساس محدودهٔ سازمان/پروژه و سطح اهمیت بررسی می‌شود.",
  "Exact-SHA physical runtime": "Runtime فیزیکی Exact-SHA",
  "Exact-artifact server sizing, deterministic test matrix and evidence for physical laboratory campaigns. Physical PASS is never inferred from source checks.": "اندازهٔ سرورها، ماتریس تست قطعی و شواهد موردنیاز آزمون آزمایشگاهی را مشخص کنید. موفقیت در بررسی کد هرگز به معنی موفقیت آزمون فیزیکی نیست.",
  "Existing Kubernetes cluster": "کلاستر Kubernetes موجود",
  "Existing Linux hosts": "میزبان‌های Linux موجود",
  "Expert authoring tools": "ابزارهای تخصصی Authoring",
  "External agent access": "دسترسی Agent خارجی",
  "External certificate": "Certificate خارجی",
  "FOUNDATION_V1 · executable foundation": "FOUNDATION_V1 · Foundation اجرایی",
  "Fleet": "ناوگان",
  "Fleet configuration": "پیکربندی Fleet",
  "Fleet overview": "نمای کلی Fleet",
  "Freeze content for approval or return it for changes.": "محتوا را برای Approval فریز کنید یا برای اصلاح برگردانید.",
  "Generated / installed runtime": "Runtime تولیدشده / نصب‌شده",
  "Give the runner exactly the hosts required by the selected tier. Roles are validated before any remote action.": "دقیقاً میزبان‌های موردنیاز سطح انتخاب‌شده را به اجراکننده بدهید. نقش‌ها پیش از هر اقدام راه‌دور اعتبارسنجی می‌شوند.",
  "Global Operations Search": "جست‌وجوی سراسری عملیات",
  "Global organization and project scope": "Scope سراسری سازمان و پروژه",
  "Global organization scope": "Scope سراسری سازمان",
  "Global project scope": "Scope سراسری پروژه",
  "Grant or update access": "اعطا یا به‌روزرسانی دسترسی",
  "Group project-authorized namespaces across managed clusters without copying workload, quota, health or cost state into a second source of truth.": "Namespaceهای مجاز یک پروژه را در چند کلاستر زیر یک فضای کاری گروه‌بندی کنید، بدون اینکه وضعیت Workload، سهمیه، سلامت یا هزینه در یک مرجع دوم کپی شود.",
  "HMAC secret env reference": "مرجع Secret مربوط به HMAC",
  "Immutable commit": "Commit تغییرناپذیر",
  "Import existing": "Import موجود",
  "Infrastructure providers": "Providerهای زیرساخت",
  "Infrastructure scope": "Scope زیرساخت",
  "Inspect desired/observed drift records when investigating configuration convergence.": "برای بررسی همگرایی پیکربندی، رکوردهای Drift مربوط به Desired/Observed را مشاهده کنید.",
  "Inspect immutable catalog releases and manage signing or promotion governance.": "Releaseهای تغییرناپذیر Catalog را مشاهده و Governance امضا یا Promotion را مدیریت کنید.",
  "Inspect scoped automation identities, MCP permissions, token expiry and recent authentication activity. Rotation and revocation use the same product authority as Administration.": "حساب‌های خودکارسازی، دسترسی MCP، تاریخ انقضای توکن‌ها و آخرین ورودها را یکجا ببینید. تعویض یا لغو دسترسی از همان سیاست‌های امنیتی بخش مدیریت پیروی می‌کند.",
  "Install & import": "نصب و Import",
  "Installer Recovery Center": "مرکز بازیابی Installer",
  "Installer console URL": "URL کنسول Installer",
  "Integrations & services": "Integrationها و سرویس‌ها",
  "Kubernetes": "Kubernetes",
  "Latest advisory": "آخرین نتیجهٔ مشورتی",
  "Leave organization/repository empty for baseline-only drift. Git credentials remain server-side and are never entered here.": "برای بررسی مغایرت فقط بر اساس Baseline، سازمان و Repository را خالی بگذارید. اطلاعات دسترسی Git روی سرور باقی می‌ماند و در این فرم وارد نمی‌شود.",
  "Lifecycle and promotion actions operate only on persisted authority records. Admission blockers are shown instead of being hidden or bypassed.": "اقدام‌های چرخهٔ عمر و ارتقای نسخه فقط روی رکوردهای رسمی ذخیره‌شده اجرا می‌شوند. هر مانع پذیرش به کاربر نشان داده می‌شود و قابل دورزدن نیست.",
  "Load a cluster workload inventory": "بارگذاری وضعیت ثبت‌شده مربوط به Workloadهای کلاستر",
  "Loading target architecture authority…": "در حال بارگذاری Authority معماری مقصد…",
  "Local, derived campaign evidence. It is not product authority and cannot certify Physical PASS.": "این شواهد از اجرای محلی به‌دست آمده‌اند و مرجع نهایی محصول نیستند؛ از آن‌ها نمی‌توان موفقیت آزمون فیزیکی را نتیجه گرفت.",
  "Low-token AI diagnosis": "تشخیص AI کم‌توکن",
  "M00–M13 are driven by the same canonical authority consumed by the CLI runner. Destructive and AI-eligible rows are explicit.": "سناریوهای M00 تا M13 از همان مرجع رسمی مورد استفادهٔ Runner اجرا می‌شوند. سناریوهای مخرب و مواردی که AI اجازهٔ تحلیل آن‌ها را دارد به‌صورت صریح مشخص شده‌اند.",
  "AI account connections": "اتصال حساب هوش مصنوعی",
  "Human users connect with their organization account, choose where the AI may work, review the requested access and keep every change inside normal approval, job, audit and evidence workflows.": "کاربر با حساب سازمانی خودش وارد می‌شود، سازمان یا پروژهٔ مجاز را انتخاب می‌کند، سطح دسترسی را پیش از اتصال می‌بیند و هر تغییری همچنان از مسیر عادی تأیید، عملیات ثبت‌شده، ممیزی و شواهد انجام می‌شود.",
  "Sign in with organization account": "ورود با حساب سازمانی",
  "Choose organization or project": "انتخاب سازمان یا پروژه",
  "Choose friendly access": "انتخاب نوع دسترسی",
  "Review and confirm": "مرور و تأیید",
  "Follow jobs and results": "پیگیری عملیات و نتیجه",
  "OAuth connection foundation": "زیرساخت اتصال OAuth",
  "Connection setup is not enabled yet": "اتصال کاربر هنوز فعال نشده است",
  "OAuth discovery and dedicated MCP audience are implemented. Revocable delegation grants, trusted-client registration and consent management are still required before human connections can be enabled.": "کشف OAuth و audience مستقل MCP آماده شده‌اند. پیش از فعال‌شدن اتصال کاربران، باید مجوزهای قابل‌لغو، ثبت کلاینت‌های مورداعتماد و مدیریت رضایت کاربر نیز تکمیل شوند.",
  "Advanced connection details": "جزئیات فنی اتصال",
  "MCP access": "دسترسی MCP",
  "MCP is read-only by default. Operators can issue separate mcp.operate credentials for allow-listed product operations; role, project, revision, approval and audit boundaries remain enforced.": "MCP به‌صورت پیش‌فرض فقط امکان مشاهده دارد. برای انجام تغییر، دسترسی جداگانه و محدود لازم است و همهٔ قوانین نقش کاربر، پروژه، تأیید و ممیزی همچنان اعمال می‌شوند.",
  "Machine name": "نام ماشین",
  "Maintenance & node operations": "Maintenance و عملیات نود",
  "Managed ACME": "ACME مدیریت‌شده",
  "Managed Kubernetes Platform": "Platform مدیریت‌شده Kubernetes",
  "Managed cluster": "کلاستر مدیریت‌شده",
  "Managed private CA": "CA خصوصی مدیریت‌شده",
  "Max unavailable (%)": "حداکثر عدم دسترس‌پذیری (%)",
  "Membership changes are scoped to the selected organization.": "تغییرات Membership به سازمان انتخاب‌شده Scope می‌شوند.",
  "Minimum severity": "حداقل Severity",
  "Must be unused for the first INSTALL attempt. Existing namespaces are not overwritten.": "برای اولین تلاش INSTALL باید استفاده‌نشده باشد. Namespaceهای موجود بازنویسی نمی‌شوند.",
  "Namespace": "فضای نام (Namespace)",
  "Namespace bindings": "Bindingهای Namespace",
  "Namespaces owned by the payments platform team": "Namespaceهای متعلق به تیم Platform پرداخت",
  "Need raw validation, compatibility evaluation or a planning-only result?": "به Validation خام، ارزیابی سازگاری یا نتیجه فقط-Planning نیاز دارید؟",
  "New secret reference": "مرجع Secret جدید",
  "No AI diagnosis has been requested in this session.": "در این Session هیچ تشخیص AI درخواست نشده است.",
  "No action is executed from this result. Verify evidence and use normal product workflows for any change.": "هیچ Actionای از این نتیجه اجرا نمی‌شود. Evidence را Verify کنید و برای هر تغییر از Workflowهای عادی محصول استفاده کنید.",
  "No direct deploy from a template.": "Deploy مستقیم از Template وجود ندارد.",
  "No environment overlay": "بدون Overlay مربوط به Environment",
  "No event or delivery is created.": "هیچ Event یا Delivery ایجاد نمی‌شود.",
  "No organization delegation": "بدون Delegation سازمان",
  "No project delegation": "بدون Delegation پروژه",
  "No provider overlay": "بدون Overlay مربوط به Provider",
  "No source release": "بدون Source Release",
  "Notifications": "اعلان‌ها",
  "OBSERVABILITY_V1 · metrics / logs / alert path": "OBSERVABILITY_V1 · مسیر Metrics / Logs / Alert",
  "One exact JSON Pointer = JSON value per line. Only paths delegated by the Blueprint ownership policy can resolve.": "هر خط شامل یک JSON Pointer دقیق و مقدار JSON آن است. فقط مسیرهایی قابل تعیین هستند که سیاست مالکیت Blueprint اجازه داده باشد.",
  "Open only when changing environment policy, maintenance windows or node state.": "فقط هنگام تغییر سیاست محیط، پنجرهٔ نگه‌داری یا وضعیت نود اقدام کنید.",
  "Open planning tools": "بازکردن ابزارهای Planning",
  "Open recovery console": "بازکردن کنسول Recovery",
  "Operations": "عملیات",
  "Operator · non-approval mutations": "Operator · Mutationهای بدون Approval",
  "Optional HMAC-SHA256 signing secret reference.": "مرجع اختیاری Secret امضای HMAC-SHA256.",
  "Optional lineage for a newly-authored release; immutable after creation.": "Lineage اختیاری برای Release تازه Author شده؛ پس از ایجاد تغییرناپذیر است.",
  "Optional. Compare the last platform-published signed revision with the current Forgejo-compatible Git head and the live revision observed by the cluster agent.": "اختیاری است. آخرین نسخهٔ امضاشدهٔ منتشرشده توسط پلتفرم را با وضعیت فعلی Git و نسخه‌ای که Agent روی کلاستر مشاهده کرده مقایسه کنید.",
  "Organization admin": "Admin سازمان",
  "Organization operator": "Operator سازمان",
  "Organization viewer": "Viewer سازمان",
  "Organization-wide": "کل سازمان",
  "Organization-wide event": "رویداد کل سازمان",
  "Organizations & projects": "سازمان‌ها و پروژه‌ها",
  "Overview": "نمای کلی",
  "Payments Team": "تیم پرداخت",
  "Physical test matrix": "ماتریس تست فیزیکی",
  "Pilot · 5 tenants": "Pilot · ۵ Tenant",
  "Plan and preflight are non-destructive. The run command requires an explicit confirmation token.": "ساخت برنامه و پیش‌بررسی هیچ تغییری ایجاد نمی‌کنند. شروع اجرا فقط پس از تأیید صریح مجاز است.",
  "Planning tools": "ابزارهای Planning",
  "Platform": "پلتفرم",
  "Platform Factory workflow": "Workflow مربوط به Platform Factory",
  "Platform admin": "Admin پلتفرم",
  "Platform blueprints": "Blueprintهای پلتفرم",
  "Platform operator": "Operator پلتفرم",
  "Platform templates": "Templateهای پلتفرم",
  "Platform viewer": "Viewer پلتفرم",
  "Platforms": "Platformها",
  "Pod security": "امنیت Pod",
  "Policies: BLUEPRINT_ONLY, PROVIDER_ONLY, ENVIRONMENT_ONLY, PROVIDER_THEN_ENVIRONMENT.": "Policyها: BLUEPRINT_ONLY، PROVIDER_ONLY، ENVIRONMENT_ONLY، PROVIDER_THEN_ENVIRONMENT.",
  "Policy & governance": "Policy و Governance",
  "Policy set": "مجموعه Policy",
  "Preview routing": "Preview مسیریابی",
  "Primary navigation": "Navigation اصلی",
  "Private organization": "سازمان خصوصی",
  "Private repository": "Repository خصوصی",
  "Product ownership boundaries. No workload state is duplicated here.": "مرزهای مالکیت محصول. هیچ Workload stateای اینجا Duplicate نمی‌شود.",
  "Production": "محیط Production",
  "Production Fleet": "Fleet مربوط به Production",
  "Production defaults favor approval, recovery checkpoints and restricted workloads.": "تنظیمات پیشنهادی محیط Production بر تأیید تغییر، نقطهٔ بازیابی و محدودسازی Workloadها تأکید دارد.",
  "Profile": "پروفایل",
  "Program tracks & continuation authority": "Trackهای برنامه و Authority ادامه کار",
  "Project admin": "Admin پروژه",
  "Project operator": "Operator پروژه",
  "Project viewer": "Viewer پروژه",
  "Provider": "ارائه‌دهنده (Provider)",
  "Provider actions": "Actionهای Provider",
  "Provider/model, linked authority, prompt/context/output digests, token usage and redaction count. Raw prompts and credentials are not persisted.": "نام سرویس و مدل، مرجع عملیات، شناسه‌های یکپارچگی ورودی و خروجی، میزان مصرف و تعداد موارد حذف‌شدهٔ حساس ثبت می‌شود. متن خام درخواست و اطلاعات محرمانه ذخیره نمی‌شوند.",
  "Provision a namespace tenant after selecting its owning project, target cluster and plan.": "پس از انتخاب پروژه مالک، کلاستر مقصد و Plan، یک Namespace Tenant را Provision کنید.",
  "Provisioning adapter": "Adapter مربوط به Provisioning",
  "Published Blueprint release": "Release منتشرشده Blueprint",
  "Published RENDER/RUNTIME/PRODUCTION releases can render their exact embedded source bundle into deterministic Kubernetes resources.": "نسخه‌های منتشرشده در سطح RENDER، RUNTIME یا PRODUCTION می‌توانند بستهٔ منبع دقیق خود را به منابع قطعی Kubernetes تبدیل کنند.",
  "Published renderable Catalog release": "Release قابل Render منتشرشده Catalog",
  "Pull request (recommended)": "Pull Request (پیشنهادی)",
  "Pull request mode stages a signed branch and requires explicit approval before merge.": "در حالت Pull Request یک شاخهٔ امضاشده برای بررسی ساخته می‌شود و ادغام آن فقط پس از تأیید صریح انجام می‌شود.",
  "QUERY · bounded history": "QUERY · تاریخچه محدود",
  "Question": "پرسش",
  "Read the effective provider configuration and non-bypassable AI authority limits. Provider reachability is not inferred from configuration alone.": "تنظیمات مؤثر سرویس هوش مصنوعی و محدودیت‌های امنیتی آن را ببینید. در دسترس‌بودن سرویس فقط از روی تنظیمات حدس زده نمی‌شود و با درخواست واقعی بررسی می‌شود.",
  "Read-only S1 source-selection authority. Review-required rows remain blocked until their exact upstream evidence is accepted; this view never promotes or acquires a component.": "وضعیت انتخاب منبع در S1 فقط برای مشاهده است. مواردی که هنوز نیاز به بررسی دارند تا ثبت شواهد معتبر upstream مسدود می‌مانند و از این صفحه هیچ مؤلفه‌ای دریافت یا ارتقا داده نمی‌شود.",
  "Read-only source material used to author catalog candidates. These records are not themselves published governed releases.": "این منابع فقط برای ساخت نسخه‌های کاندید Catalog استفاده می‌شوند. خود این رکوردها نسخهٔ منتشرشده و موردتأیید محصول نیستند.",
  "Create SLO policy": "ایجاد سیاست SLO",
  "Create incident": "ایجاد رخداد",
  "Immutable cluster-targeted SLO policy and fail-closed coverage.": "سیاست SLO تغییرناپذیر برای کلاستر انتخاب‌شده که در حالت ابهام یا نقص پوشش، نتیجه را معتبر اعلام نمی‌کند.",
  "Incidents": "رخدادها",
  "Objective (basis points)": "هدف (واحد basis point)",
  "Observation interval": "فاصلهٔ مشاهده",
  "Project-wide": "کل پروژه",
  "Reliability": "قابلیت اطمینان",
  "SLO & error budget": "SLO و بودجهٔ خطا",
  "Service": "سرویس",
  "Service health": "سلامت سرویس",
  "Service health, incidents, SLOs and error budgets for the selected project.": "سلامت سرویس، رخدادها، SLOها و بودجهٔ خطای پروژهٔ انتخاب‌شده.",
  "Window seconds": "بازهٔ زمانی (ثانیه)",
  "Recovery checkpoints": "Recovery checkpointها",
  "Recovery remains on the standalone bootstrap plane so it is available when the product API is unavailable, reset or being reinstalled.": "بازیابی روی بخش مستقل راه‌اندازی باقی می‌ماند تا حتی وقتی API محصول در دسترس نیست، بازنشانی شده یا دوباره نصب می‌شود، امکان بازیابی وجود داشته باشد.",
  "Reference-only authority.": "Authority فقط-مرجع.",
  "Register or inspect backup evidence before disruptive maintenance and upgrades.": "پیش از نگه‌داری یا ارتقای مخرب، وجود و اعتبار نسخهٔ پشتیبان را ثبت یا بررسی کنید.",
  "Register recovery checkpoint": "ثبت Recovery checkpoint",
  "Register signing trust or create a candidate when changing catalog authority.": "هنگام تغییر مرجع کنترل کاتالوگ، اعتماد به امضا را ثبت کنید یا نسخهٔ نامزد بسازید.",
  "Register the configured Ed25519 signer as platform-wide or organization-private trust. The private signing key is never returned to the browser.": "امضاکنندهٔ Ed25519 پیکربندی‌شده را برای کل پلتفرم یا فقط یک سازمان مورداعتماد کنید. کلید خصوصی امضا هرگز به مرورگر فرستاده نمی‌شود.",
  "Register verified backup/recovery evidence against the current cluster inventory before scheduling an upgrade.": "شواهد تأییدشدهٔ پشتیبان‌گیری و بازیابی را پیش از زمان‌بندی ارتقا در برابر وضعیت فعلی کلاستر ثبت کنید.",
  "Release identity": "هویت Release",
  "Render": "رندر",
  "Render target namespace": "Namespace مقصد Render",
  "Repository name": "نام Repository",
  "Require approval": "الزام Approval",
  "Require recovery checkpoint": "الزام Recovery checkpoint",
  "Required certification": "Certification موردنیاز",
  "Restricted egress": "Egress محدودشده",
  "Retention": "نگهداشت",
  "Retire normally or revoke a release that must no longer be selected.": "نسخه‌ای را که دیگر استفاده نمی‌شود بازنشسته کنید، یا اگر نباید دوباره انتخاب شود دسترسی به آن را لغو کنید.",
  "Review delivery health and history before changing destinations or routing.": "پیش از تغییر مقصد یا مسیر اعلان، وضعیت سلامت و سابقهٔ ارسال را بررسی کنید.",
  "Review upgrade lineage and create the immutable draft revision.": "سابقهٔ ارتقا را بررسی کنید و یک پیش‌نویس بازنگری تغییرناپذیر بسازید.",
  "Revoke active credential": "Revoke کردن Credential فعال",
  "Risk class": "کلاس Risk",
  "Rotate credential reference": "Rotate کردن مرجع اطلاعات دسترسی",
  "Routing preview": "Preview مسیریابی",
  "Routing rules": "Ruleهای مسیریابی",
  "Rule name": "نام Rule",
  "Run a new verification, closure campaign or physical-runtime certification.": "اعتبارسنجی، دور تکمیل یا تأیید زمان اجرای فیزیکی جدید اجرا کنید.",
  "Run the lab": "اجرای Lab",
  "Runtime & delivery": "Runtime و Delivery",
  "Runtime & safety boundary": "مرز Runtime و Safety",
  "Runtime assurance": "تضمین Runtime",
  "Runtime-realism negative controls": "Negative Controlهای Runtime-realism",
  "Scope": "محدوده",
  "Scope & publish": "Scope و Publish",
  "Search": "جست‌وجو",
  "Search operations": "جست‌وجوی عملیات",
  "Search pages and operator workflows": "جست‌وجوی صفحه‌ها و Workflowهای Operator",
  "Search the bounded, rebuildable 4SO project projection across clusters, operations, evidence metadata and scoped audit. PostgreSQL is the default bounded backend; OpenSearch is optional for scale and never becomes source of truth.": "نمای محدود و قابل‌بازسازی پروژه 4SO را در کلاسترها، عملیات، فرادادهٔ شواهد و ممیزی محدودشده جست‌وجو کنید. PostgreSQL مرجع پیش‌فرض است؛ OpenSearch برای مقیاس‌پذیری اختیاری است و هرگز مرجع اصلی داده نمی‌شود.",
  "Secret reference": "مرجع Secret",
  "Section navigation": "Navigation بخش",
  "Security policy": "Policy امنیتی",
  "Select an operation or connected cluster. The platform builds and redacts the context; raw credentials are never entered here.": "یک عملیات یا کلاستر متصل را انتخاب کنید. پلتفرم اطلاعات لازم را جمع‌آوری و داده‌های حساس را حذف می‌کند؛ رمز، کلید یا توکن خام در این بخش وارد نمی‌شود.",
  "Select level": "انتخاب سطح",
  "Select one or more active destinations.": "فقط یک یا چند Destination فعال را انتخاب کنید.",
  "Select only the components that belong to this immutable catalog release. Resolved embedded components are selected by default; unresolved research records remain opt-in.": "فقط Componentهایی را انتخاب کنید که متعلق به این نسخهٔ تغییرناپذیر کاتالوگ هستند. Componentهای درج‌شده و حل‌شده به‌صورت پیش‌فرض انتخاب می‌شوند؛ رکوردهای پژوهشی حل‌نشده فقط با انتخاب صریح وارد می‌شوند.",
  "Select type": "انتخاب نوع",
  "Select version": "انتخاب نسخه",
  "Server tiers": "Tierهای سرور",
  "Server-side references and operational state only; credential values are never returned.": "فقط مرجع‌های سمت سرور و وضعیت عملیاتی نمایش داده می‌شوند؛ مقدار رمز، کلید یا توکن هرگز به مرورگر برگردانده نمی‌شود.",
  "Service Provider · 1000 tenants + white-label": "Service Provider · ۱۰۰۰ Tenant + White-label",
  "Set field ownership, approval, security, tenancy and evidence policy.": "مشخص کنید هر فیلد متعلق به کدام لایه است و سیاست‌های تأیید، امنیت، چندمستاجری و نگه‌داری شواهد را تنظیم کنید.",
  "Severity": "شدت",
  "Shipped catalog · legacy binding": "Catalog عرضه‌شده · Binding قدیمی",
  "Shipped component source inventory": "وضعیت ثبت‌شده مربوط به Source مؤلفه‌های عرضه‌شده",
  "Signed platform desired state": "Desired State امضاشده Platform",
  "Signing trust": "اعتماد امضا",
  "Source semantics": "معنای Source",
  "Staging": "مرحله Staging",
  "Start / Overview": "شروع / نمای کلی",
  "Start assurance workflow": "شروع Workflow تضمین",
  "Supply-chain releases": "Releaseهای Supply-chain",
  "Support & Diagnostics Center": "مرکز Support و Diagnostics",
  "Support & diagnostics": "Support و Diagnostics",
  "Supported types: STRING, INTEGER, BOOLEAN, STRING_LIST. Unknown values fail closed when resolved.": "نوع‌های پشتیبانی‌شده: STRING، INTEGER، BOOLEAN، STRING_LIST. مقدارهای ناشناخته هنگام حل تنظیمات رد می‌شوند.",
  "TAIL · bounded latest snapshot": "TAIL · آخرین Snapshot محدود",
  "TARGET PREVIEW REQUIRED": "پیش‌نمایش مقصد الزامی است",
  "TARGET_RUNTIME_V1 · target capabilities + foundation harness": "TARGET_RUNTIME_V1 · Capabilityهای مقصد + Foundation harness",
  "Tag": "برچسب (Tag)",
  "Target identity is independent from provisioning: Cluster API is a provisioning adapter, while": "هویت مقصد از Provisioning مستقل است: Cluster API یک Provisioning Adapter است، درحالی‌که",
  "Target runtime": "Runtime مقصد",
  "Tenancy mode": "حالت Tenancy",
  "Tenant environments & branding": "Environmentهای Tenant و Branding",
  "The API validator intentionally rejects unsafe values; the visual editor represents the exact API fields rather than silently hardcoding them.": "اعتبارسنج API مقدارهای ناامن را رد می‌کند. ویرایشگر تصویری نیز همان فیلدهای واقعی API را نشان می‌دهد و هیچ مقدار پنهانی را به‌جای کاربر ثبت نمی‌کند.",
  "The bootstrap token is entered directly in the Installer Recovery Console and is never stored or proxied by this panel.": "توکن راه‌اندازی فقط در کنسول بازیابی نصب‌کننده وارد می‌شود و این پنل آن را ذخیره یا واسطه‌گری نمی‌کند.",
  "The canonical product roadmap and its cross-cutting tracks prevent backend-only closure. This is live from the target architecture authority, not copied roadmap prose.": "نقشهٔ راه اصلی محصول و مسیرهای مشترک آن اجازه نمی‌دهند یک قابلیت فقط با آماده‌شدن Backend کامل اعلام شود. این وضعیت مستقیماً از مرجع معماری محصول خوانده می‌شود، نه از متن ثابت مستندات.",
  "The current maintenance contract enforces one node at a time.": "در وضعیت فعلی، عملیات نگه‌داری فقط روی یک نود در هر لحظه اجرا می‌شود.",
  "Three-way Git drift source": "Source سه‌طرفه Git Drift",
  "Timeout (seconds)": "Timeout (ثانیه)",
  "Toggle color theme": "تغییر Theme رنگ",
  "Toggle navigation": "باز/بسته کردن Navigation",
  "Trust configured signer": "اعتماد به Signer پیکربندی‌شده",
  "Trust key name": "نام Trust Key",
  "Trust scope": "Scope اعتماد",
  "Upstream acquisition admission": "Admission مربوط به Upstream Acquisition",
  "Use as default managed Git provider": "استفاده به‌عنوان Provider پیش‌فرض Managed Git",
  "Use strict JSON definitions; sensitive variables cannot have defaults.": "از تعریف‌های JSON سخت‌گیرانه استفاده کنید؛ متغیرهای حساس نمی‌توانند مقدار پیش‌فرض داشته باشند.",
  "Use this only when establishing a new ownership boundary.": "فقط هنگام ایجاد یک مرز مالکیت جدید از این مورد استفاده کنید.",
  "Username": "نام کاربری",
  "Variable definitions (JSON array)": "Definitionهای Variable (آرایه JSON)",
  "Variable schema": "Schema مربوط به Variable",
  "Verify a profile or provision a dedicated target when infrastructure changes.": "هنگام تغییر زیرساخت، یک Profile را Verify کنید یا مقصد اختصاصی Provision کنید.",
  "Verify a published Catalog release against fresh cluster inventory and collect evidence for the selected certification profile.": "نسخهٔ منتشرشدهٔ Catalog را با آخرین وضعیت کلاستر بررسی کنید و شواهد لازم برای سطح تأیید انتخاب‌شده را جمع‌آوری کنید.",
  "Viewer · read only": "Viewer · فقط‌خواندنی",
  "Visibility": "قابلیت مشاهده",
  "Webhook": "وب‌هوک",
  "Webhook endpoint": "Endpoint مربوط به Webhook",
  "Why did this operation fail, what owner layer should be checked, and what is the safest next verification?": "چرا این عملیات ناموفق شد، مشکل احتمالاً در کدام بخش است و امن‌ترین بررسی بعدی چیست؟",
  "Workspace": "فضای کاری",
  "Workspace records": "رکوردهای Workspace",
  "Workspaces": "Workspaceها",
  "Your cloud brand": "Brand ابری شما",
  "are distribution identities. Installer history such as Kubespray is not a distribution identity.": "این موارد هویت توزیع هستند. سابقهٔ نصب‌کننده‌هایی مانند Kubespray هویت توزیع محسوب نمی‌شود.",
  "event, actor, target, message…": "رویداد، Actor، مقصد، پیام…",
  "upgrade failure, cluster name, evidence kind…": "خطای Upgrade، نام کلاستر، نوع Evidence…",
  "vSphere Standard": "استاندارد vSphere",
  "vsphere or production": "vsphere یا production",
  "· selected source:": "· Source انتخاب‌شده:",
  "COMPONENT_RUNTIME_V1 · exact component lifecycle evidence": "COMPONENT_RUNTIME_V1 · شواهد دقیق چرخهٔ عمر مؤلفه",
  "Component": "مؤلفه",
  "Create an evidence-bound certification run from a published renderable Catalog release and fresh cluster inventory. FOUNDATION_V1 proves the executable foundation. OBSERVABILITY_V1 executes real metrics, logs and alert paths. TARGET_RUNTIME_V1 proves target-cluster networking, storage, backup/restore and observability capabilities. COMPONENT_RUNTIME_V1 is component-specific: it binds an exact component release and source lock, executes fresh install, readiness/dependency checks, controlled failure/recovery and safe removal, and remains partial until a real admitted version-to-version upgrade is certified. Missing providers or lifecycle authority remain BLOCKED.": "از یک انتشار کاتالوگ منتشرشده و قابل اجرا، همراه با موجودی تازهٔ کلاستر، یک اجرای اعتبارسنجی متصل به شواهد بسازید. FOUNDATION_V1 پایهٔ اجرایی را بررسی می‌کند. OBSERVABILITY_V1 مسیر واقعی متریک‌ها، لاگ و هشدار را می‌آزماید. TARGET_RUNTIME_V1 قابلیت‌های شبکه، ذخیره‌سازی، پشتیبان‌گیری و بازیابی و پایش کلاستر مقصد را بررسی می‌کند. COMPONENT_RUNTIME_V1 مخصوص یک مؤلفهٔ مشخص است: نسخهٔ دقیق و قفل منبع همان مؤلفه را ثبت می‌کند، نصب تازه، آمادگی، وابستگی‌ها، خرابی کنترل‌شده و بازیابی، و حذف امن را اجرا می‌کند. این پروفایل تا زمانی که ارتقای واقعی بین دو نسخهٔ پذیرفته‌شده تأیید نشود، همچنان ناقص می‌ماند. اگر ارائه‌دهنده یا اختیار چرخهٔ عمر موجود نباشد، وضعیت BLOCKED باقی می‌ماند.",
  "Durable phase state with inventory/source-lock/render binding, fenced checkpoints, evidence, expiry and explicit BLOCKED/FAILED states. Component runs continue through FAILURE_RECOVERY and REMOVE; upgrade remains separately gated.": "وضعیت هر مرحله به‌صورت پایدار همراه با موجودی، قفل منبع، خروجی تولیدشده، قفل اجرایی، نقطهٔ بازیابی، شواهد و زمان انقضا نگه‌داری می‌شود و حالت‌های BLOCKED/FAILED صریح هستند. اجرای مؤلفه پس از بررسی اولیه وارد FAILURE_RECOVERY و سپس REMOVE می‌شود؛ ارتقا همچنان شرط عبور مستقل خود را دارد.",
  "Must be unused for the first INSTALL attempt. Existing resources are never adopted or overwritten.": "برای اولین تلاش INSTALL، Namespace باید خالی و استفاده‌نشده باشد. منبع موجود هرگز پذیرفته یا بازنویسی نمی‌شود.",
  "Only source-ready components with an admitted component-owned executor are listed. Upgrade remains independently gated.": "فقط مؤلفه‌هایی نمایش داده می‌شوند که منبع آن‌ها آماده است و اجراکنندهٔ اختصاصی پذیرفته‌شده دارند. ارتقا همچنان شرط عبور مستقل خود را دارد.",
};
const dynamicOriginalText = new WeakMap();
const dynamicOriginalAttributes = new WeakMap();
let dynamicLocalizationBusy = false;
const localizedAttributeNames = ['aria-label','placeholder','title'];
function localizeDynamicText(text) {
  const value=String(text??'');
  return state.locale==='fa'?(faDynamic[value]||value):value;
}

function localizeDynamicTree(root = document.body) {
  if (!root || dynamicLocalizationBusy) return; dynamicLocalizationBusy = true;
  const walker=document.createTreeWalker(root,NodeFilter.SHOW_TEXT),nodes=[];while(walker.nextNode())nodes.push(walker.currentNode);
  for(const node of nodes){const parent=node.parentElement;if(!parent||parent.closest('script,style,pre,code,.technical,[data-i18n]'))continue;const trimmed=node.nodeValue.trim();if(state.locale==='fa'&&faDynamic[trimmed]){if(!dynamicOriginalText.has(node))dynamicOriginalText.set(node,node.nodeValue);const lead=node.nodeValue.match(/^\s*/)?.[0]||'',trail=node.nodeValue.match(/\s*$/)?.[0]||'';node.nodeValue=lead+faDynamic[trimmed]+trail;}else if(state.locale!=='fa'&&dynamicOriginalText.has(node)){node.nodeValue=dynamicOriginalText.get(node);dynamicOriginalText.delete(node);}}
  dynamicLocalizationBusy=false;
}
function localizeDynamicAttributes(root = document.body) {
  if (!root || dynamicLocalizationBusy) return; dynamicLocalizationBusy = true;
  const elements = [root, ...root.querySelectorAll('*')].filter(el => el?.getAttribute && !el.closest?.('.technical'));
  for (const el of elements) {
    let originals = dynamicOriginalAttributes.get(el);
    for (const attr of localizedAttributeNames) {
      const current = el.getAttribute(attr);
      if (state.locale === 'fa') {
        if (!current || !faDynamic[current]) continue;
        if (!originals) { originals = new Map(); dynamicOriginalAttributes.set(el, originals); }
        if (!originals.has(attr)) originals.set(attr, current);
        el.setAttribute(attr, faDynamic[current]);
      } else if (originals?.has(attr)) {
        el.setAttribute(attr, originals.get(attr));
        originals.delete(attr);
      }
    }
    if (originals && originals.size === 0) dynamicOriginalAttributes.delete(el);
  }
  dynamicLocalizationBusy=false;
}
let dynamicLocalizationScheduled=false;
const dynamicLocalizationObserver=new MutationObserver(()=>{
  if(dynamicLocalizationBusy||state.locale!=='fa'||dynamicLocalizationScheduled)return;
  dynamicLocalizationScheduled=true;
  requestAnimationFrame(()=>{dynamicLocalizationScheduled=false;localizeDynamicTree(document.body);localizeDynamicAttributes(document.body);});
});
dynamicLocalizationObserver.observe(document.body,{subtree:true,childList:true,characterData:true,attributes:true,attributeFilter:localizedAttributeNames});

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
  {value:'read,mcp.read,mcp.operate',label:'MCP delegated operator'},
  {value:'read,operation.execute',label:'Operation executor'},
  {value:'read,operate,mcp.read,mcp.operate,ai.diagnose,operation.execute',label:'Full operator automation + executor'}
] : [
  {value:'read',label:'Read only'},
  {value:'read,mcp.read',label:'Read + MCP context'}
];
const apiTokenPermissionsFromProfile = value => String(value||'read').split(',').map(item=>item.trim()).filter(Boolean);
const apiTokenPermissionProfileValue = permissions => {
  const values=new Set(permissions||[]);
  if(values.has('operate')&&values.has('mcp.read')&&values.has('mcp.operate')&&values.has('ai.diagnose'))return 'read,operate,mcp.read,mcp.operate,ai.diagnose';
  if(values.has('mcp.operate'))return 'read,mcp.read,mcp.operate';
  if(values.has('ai.diagnose'))return 'read,mcp.read,ai.diagnose';
  if(values.has('mcp.read'))return 'read,mcp.read';
  if(values.has('operate'))return 'read,operate,mcp.read,mcp.operate,ai.diagnose';
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

function scopeDirectoryProject(projectId) {
  return state.scopeProjects.find(item=>item.id===projectId)||null;
}
function scopeDirectoryOrganization(organizationId) {
  return state.scopeOrganizations.find(item=>item.id===organizationId)||null;
}
function globalScopeProjectIDs() {
  if(state.globalScope.projectId)return new Set([state.globalScope.projectId]);
  if(state.globalScope.organizationId)return new Set(state.scopeProjects.filter(item=>item.organizationId===state.globalScope.organizationId).map(item=>item.id));
  return null;
}
function projectBelongsToGlobalScope(projectId) {
  if(!projectId)return true;
  if(state.globalScope.projectId)return projectId===state.globalScope.projectId;
  if(!state.globalScope.organizationId)return true;
  return scopeDirectoryProject(projectId)?.organizationId===state.globalScope.organizationId;
}
function organizationBelongsToGlobalScope(organizationId) {
  if(!organizationId||!state.globalScope.organizationId)return true;
  return organizationId===state.globalScope.organizationId;
}
function persistGlobalScope() {
  if(state.globalScope.organizationId)localStorage.setItem('platformScopeOrganization',state.globalScope.organizationId);
  else localStorage.removeItem('platformScopeOrganization');
  if(state.globalScope.projectId)localStorage.setItem('platformScopeProject',state.globalScope.projectId);
  else localStorage.removeItem('platformScopeProject');
}
function normalizeGlobalScope() {
  let organizationId=String(state.globalScope.organizationId||'').trim();
  let projectId=String(state.globalScope.projectId||'').trim();
  const fixedProject=String(state.accessContext?.projectId||'').trim();
  const fixedOrganization=String(state.accessContext?.organizationId||'').trim();
  if(fixedProject)projectId=fixedProject;
  if(fixedOrganization)organizationId=fixedOrganization;

  const project=scopeDirectoryProject(projectId);
  if(projectId&&!project)projectId='';
  if(projectId){
    organizationId=scopeDirectoryProject(projectId)?.organizationId||organizationId;
  }
  if(organizationId&&!scopeDirectoryOrganization(organizationId))organizationId='';
  if(projectId&&organizationId&&scopeDirectoryProject(projectId)?.organizationId!==organizationId)projectId='';

  state.globalScope={organizationId,projectId};
  persistGlobalScope();
  return state.globalScope;
}
function globalScopeRoleLabel() {
  if(state.globalScope.projectId)return effectiveProjectRole(state.globalScope.projectId)||'project access';
  if(state.globalScope.organizationId)return effectiveOrganizationRole(state.globalScope.organizationId)||'organization access';
  return isLocalSession()?'local admin':(state.accessContext?.globalRole||sessionRoles()[0]||'accessible scope');
}
function renderGlobalScope() {
  const root=$('#global-scope'),organization=$('#global-organization-scope'),project=$('#global-project-scope'),status=$('#global-scope-status');
  if(!root||!organization||!project||!status)return;
  normalizeGlobalScope();
  const faScope=state.locale==='fa';
  root.querySelector('label:first-of-type > span').textContent=faScope?'سازمان':'Organization';
  root.querySelector('label:nth-of-type(2) > span').textContent=faScope?'پروژه':'Project';
  const fixedProject=String(state.accessContext?.projectId||'').trim();
  const fixedOrganization=String(state.accessContext?.organizationId||'').trim();
  const orgs=state.scopeOrganizations;
  organization.innerHTML=`<option value="">${esc(faScope?'همه سازمان‌های مجاز':'All accessible organizations')}</option>${orgs.map(item=>`<option value="${esc(item.id)}">${esc(item.displayName||item.name||item.id)}</option>`).join('')}`;
  organization.value=state.globalScope.organizationId;
  const projects=state.scopeProjects.filter(item=>!state.globalScope.organizationId||item.organizationId===state.globalScope.organizationId);
  const orgNames=new Map(state.scopeOrganizations.map(item=>[item.id,item.displayName||item.name||item.id]));
  const allLabel=state.globalScope.organizationId?(faScope?'همه پروژه‌های این سازمان':'All projects in organization'):(faScope?'همه پروژه‌های مجاز':'All accessible projects');
  project.innerHTML=`<option value="">${esc(allLabel)}</option>${projects.map(item=>`<option value="${esc(item.id)}">${esc(state.globalScope.organizationId?(item.displayName||item.name||item.id):`${orgNames.get(item.organizationId)||item.organizationId} / ${item.displayName||item.name||item.id}`)}</option>`).join('')}`;
  project.value=state.globalScope.projectId;
  organization.disabled=!state.scopeReady||state.scopeTransitioning||Boolean(fixedOrganization||fixedProject);
  project.disabled=!state.scopeReady||state.scopeTransitioning||Boolean(fixedProject)||projects.length===0;
  root.dataset.ready=state.scopeReady?'true':'false';
  const org=scopeDirectoryOrganization(state.globalScope.organizationId),prj=scopeDirectoryProject(state.globalScope.projectId);
  const allName=faScope?'همه محدوده‌های مجاز':'All accessible';
  const scopeName=prj?(prj.displayName||prj.name||prj.id):org?(org.displayName||org.name||org.id):allName;
  status.textContent=state.scopeTransitioning?(faScope?'در حال تغییر محدوده…':'Switching scope…'):state.scopeReady?`${scopeName} · ${globalScopeRoleLabel()}`:(faScope?'محدوده دسترسی در دسترس نیست':'Scope authority unavailable');
}
async function refreshGlobalScopeDirectory() {
  try{
    const [organizations,projects]=await Promise.all([authorityJSON('/api/v1/organizations'),authorityJSON('/api/v1/projects')]);
    state.scopeOrganizations=Array.isArray(organizations)?organizations:[];
    state.scopeProjects=Array.isArray(projects)?projects:[];
    state.scopeReady=true;
    normalizeGlobalScope();
    renderGlobalScope();
    return true;
  }catch(error){
    state.scopeReady=false;
    state.scopeOrganizations=[];
    state.scopeProjects=[];
    renderGlobalScope();
    return false;
  }
}
async function changeGlobalScope(nextOrganizationId,nextProjectId) {
  const nextProject=scopeDirectoryProject(nextProjectId);
  let organizationId=String(nextOrganizationId||'').trim();
  let projectId=String(nextProjectId||'').trim();
  if(projectId&&nextProject)organizationId=nextProject.organizationId;
  if(projectId&&!nextProject)projectId='';
  if(organizationId&&!scopeDirectoryOrganization(organizationId))organizationId='';
  if(projectId&&scopeDirectoryProject(projectId)?.organizationId!==organizationId)projectId='';
  if(organizationId===state.globalScope.organizationId&&projectId===state.globalScope.projectId)return false;

  if(hasUnsavedChanges()){
    const discarded=await confirmAction('Change organization/project scope?','Changing global scope reloads this page from a different authority boundary and will discard unsaved changes.',true);
    if(!discarded){renderGlobalScope();return false;}
  }
  clearDirtyForms();
  state.scopeTransitioning=true;
  state.pageLoadController?.abort();
  state.globalScope={organizationId,projectId};
  persistGlobalScope();
  renderGlobalScope();
  applyAccessMode();
  try{
    await loadPage(state.currentPage,true);
    return true;
  }finally{
    state.scopeTransitioning=false;
    renderGlobalScope();
    applyAccessMode();
  }
}
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
  setScopedAccess($('#target-node-lifecycle-grid'),{projectId:maintenanceProject,access:'read'});

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
  setScopedAccess($('#ai-diagnosis-form'),{projectId:$('#ai-project')?.value||''});
  setScopedAccess($('#template-schema-form'),{projectId:$('#template-schema-project')?.value||''});
  setScopedAccess($('#template-policy-form'),{projectId:$('#template-policy-project')?.value||''});
  setScopedAccess($('#platform-template-form'),{projectId:$('#platform-template-project')?.value||''});
  setScopedAccess($('#workspace-authority-form'),{projectId:$('#workspace-authority-project')?.value||''});
  const selectedWorkspace=state.workspaces.find(item=>item.id===$('#workspace-binding-workspace')?.value);
  setScopedAccess($('#workspace-binding-form'),{projectId:selectedWorkspace?.projectId||''});

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
  scopeActionElements('[data-workspace-binding-action]',state.workspaceBindings,(el,item)=>el.dataset.id===item.id,(el,item)=>({projectId:item.projectId||state.workspaces.find(workspace=>workspace.id===item.workspaceId)?.projectId||'',access:el.dataset.workspaceBindingAction==='revoke'?'write':'read'}));
  scopeActionElements('[data-catalog-trust-action]',state.catalogTrustKeys,(el,item)=>el.dataset.id===item.id,(_el,item)=>item.organizationId?({organizationId:item.organizationId,access:'admin'}):({requiredGlobalRole:'platform-admin'}));
  scopeActionElements('[data-catalog-action]',state.catalogReleases,(el,item)=>el.dataset.id===item.id,(el,item)=>{
    const admin=['request-changes','publish','deprecate','revoke'].includes(el.dataset.catalogAction);
    if(item.visibility==='PLATFORM')return {requiredGlobalRole:'platform-admin'};
    return {organizationId:item.organizationId||'',access:admin?'admin':'write'};
  });
}
function actionStateUnavailable(resourceType, action, stateValue, detail='') {
  const suffix=detail?` ${detail}`:'';
  return `${action} is unavailable while ${resourceType} is ${stateValue||'UNKNOWN'}.${suffix} Refresh authoritative state before retrying.`;
}
const statefulMutationActionKeys=new Set([
  'importAction','providerProfileAction','providerClusterAction','marketplaceAction','baselineAction','verificationAction','certificationAction','closureAction','recoveryAction','upgradeAction','tenantAction',
  'serviceAccountAction','apiTokenAction','notificationDestinationAction','notificationRouteAction','gitProviderAction','gitCredentialAction','blueprintAction','catalogAction','gitPrAction',
  'clusterAction','agentCertificateAction','maintenanceWindowAction','maintenanceRunAction','driftAction','fleetAction','workspaceBindingAction','catalogTrustAction','operationAction'
]);
function operationalActionStateReason(button) {
  const find=(items,id)=>items.find(item=>String(item?.id||'')===String(id||''));
  const action=(name)=>String(button.dataset[name]||'').toLowerCase();
  let item,a,actionContractHandled=false;
  if(button.dataset.importAction){actionContractHandled=true;item=find(state.imports,button.dataset.id);a=action('importAction');if(!item)return 'Enrollment request is no longer in the current result set. Refresh before acting.';if(a==='approve'&&item.state!=='PENDING_APPROVAL')return actionStateUnavailable('enrollment request','Approve',item.state);if(a==='revoke'&&!['PENDING_APPROVAL','APPROVED'].includes(item.state))return actionStateUnavailable('enrollment request','Cancel enrollment',item.state);}
  if(button.dataset.providerProfileAction){actionContractHandled=true;item=find(state.providerProfiles,button.dataset.id);a=action('providerProfileAction');if(!item)return 'Provider profile is no longer in the current result set. Refresh before acting.';if(a==='retry'&&item.state!=='FAILED')return actionStateUnavailable('provider profile','Retry verification',item.state);}
  if(button.dataset.providerClusterAction){actionContractHandled=true;item=find(state.providerClusters,button.dataset.id);a=action('providerClusterAction');if(!item)return 'Provider cluster is no longer in the current result set. Refresh before acting.';const allowed={approve:['AWAITING_APPROVAL','DELETE_AWAITING_APPROVAL'],scale:['ACTIVE'],upgrade:['ACTIVE'],retry:['FAILED'],delete:['ACTIVE','FAILED','DELETE_AWAITING_APPROVAL','DELETE_QUEUED']};if(allowed[a]&&!allowed[a].includes(item.state))return actionStateUnavailable('provider cluster',a,item.state);if(a==='retry'&&!['PROVISION','SCALE','UPGRADE'].includes(String(item.pendingAction||'')))return actionStateUnavailable('provider cluster','Retry',item.state,'The failed action is not retryable; use a fresh recovery-bound request when required.');}
  if(button.dataset.marketplaceAction){actionContractHandled=true;item=state.marketplaceInstallations.map(v=>v.installation||v).find(v=>String(v.id)===String(button.dataset.id));a=action('marketplaceAction');if(!item)return 'Marketplace installation is no longer in the current result set. Refresh before acting.';const allowed={approve:['AWAITING_APPROVAL'],retry:['FAILED'],uninstall:['SUCCEEDED','FAILED','ROLLBACK_QUEUED']};if(allowed[a]&&!allowed[a].includes(item.state))return actionStateUnavailable('marketplace installation',a,item.state);if(a==='retry'&&String(item.pendingAction||'')==='ROLLBACK')return actionStateUnavailable('marketplace installation','Retry',item.state,'Rollback failure requires a fresh recovery-bound uninstall request.');}
  if(button.dataset.baselineAction){actionContractHandled=true;item=find(state.baselineDeployments,button.dataset.id);a=action('baselineAction');if(!item)return 'Baseline deployment is no longer in the current result set. Refresh before acting.';const allowed={approve:['AWAITING_APPROVAL'],revalidate:['AWAITING_APPROVAL','QUEUED'],retry:['FAILED'],rollback:['SUCCEEDED','FAILED','ROLLBACK_QUEUED']};if(allowed[a]&&!allowed[a].includes(item.state))return actionStateUnavailable('baseline deployment',a,item.state);if(a==='approve'&&!planApprovalReady(item))return 'Approval is blocked until impact, rollback and evidence prerequisites are ready.';if(a==='retry'&&String(item.pendingAction||'')==='ROLLBACK')return actionStateUnavailable('baseline deployment','Retry',item.state,'Rollback failure requires a fresh recovery-bound rollback request.');}
  if(button.dataset.verificationAction){actionContractHandled=true;item=find(state.verifications,button.dataset.id);a=action('verificationAction');if(!item)return 'Runtime verification is no longer in the current result set. Refresh before acting.';if(a==='retry'&&item.state!=='FAILED')return actionStateUnavailable('runtime verification','Retry',item.state);}
  if(button.dataset.certificationAction){actionContractHandled=true;item=find(state.runtimeCertifications,button.dataset.id);a=action('certificationAction');if(!item)return 'Runtime certification is no longer in the current result set. Refresh before acting.';if(a==='revoke'&&item.state!=='SUCCEEDED')return actionStateUnavailable('runtime certification','Revoke evidence',item.state);}
  if(button.dataset.closureAction){actionContractHandled=true;item=find(state.closures,button.dataset.id);a=action('closureAction');if(!item)return 'Runtime closure campaign is no longer in the current result set. Refresh before acting.';if(a==='advance'&&['SUCCEEDED','FAILED'].includes(item.state))return actionStateUnavailable('runtime closure campaign','Advance',item.state);if(a==='retry'&&item.state!=='FAILED')return actionStateUnavailable('runtime closure campaign','Retry',item.state);if(a==='verify'&&item.state!=='SUCCEEDED')return actionStateUnavailable('runtime closure campaign','Verify evidence',item.state);}
  if(button.dataset.recoveryAction){actionContractHandled=true;item=find(state.recoveryCheckpoints,button.dataset.id);a=action('recoveryAction');if(!item)return 'Recovery checkpoint is no longer in the current result set. Refresh before acting.';if(a==='revoke'&&item.state!=='VERIFIED')return actionStateUnavailable('recovery checkpoint','Revoke',item.state);}
  if(button.dataset.upgradeAction){actionContractHandled=true;item=find(state.upgradeCampaigns,button.dataset.id);a=action('upgradeAction');if(!item)return 'Upgrade campaign is no longer in the current result set. Refresh before acting.';const allowed={approve:['AWAITING_APPROVAL'],revalidate:['AWAITING_APPROVAL','QUEUED','RUNNING','PAUSED'],pause:['RUNNING'],resume:['PAUSED'],advance:['QUEUED','RUNNING','HALTED','PAUSE_REQUESTED','CANCEL_REQUESTED'],cancel:['AWAITING_APPROVAL','QUEUED','RUNNING','HALTED','PAUSE_REQUESTED','PAUSED']};if(allowed[a]&&!allowed[a].includes(item.state))return actionStateUnavailable('upgrade campaign',a,item.state);if(a==='revalidate'&&item.state==='RUNNING'&&(item.targets||[]).some(target=>['PLANNING','APPLYING','VERIFYING','ROLLING_BACK'].includes(target.state)))return 'Revalidation is available only between waves; an active target is still running.';}
  if(button.dataset.tenantAction){actionContractHandled=true;item=find(state.tenants,button.dataset.id);a=action('tenantAction');if(!item)return 'Tenant is no longer in the current result set. Refresh before acting.';const allowed={resize:['ACTIVE'],suspend:['ACTIVE'],resume:['SUSPENDED'],approve:['RESIZE_AWAITING_APPROVAL','DELETE_AWAITING_APPROVAL'],retry:['FAILED'],delete:['ACTIVE','SUSPENDED','FAILED','DELETE_AWAITING_APPROVAL','DELETE_QUEUED']};if(allowed[a]&&!allowed[a].includes(item.state))return actionStateUnavailable('tenant',a,item.state);if(a==='retry'&&String(item.pendingAction||'')==='DELETE')return actionStateUnavailable('tenant','Retry',item.state,'Protected delete failure requires a fresh recovery-bound delete request.');}
  if(button.dataset.serviceAccountAction){actionContractHandled=true;item=find(state.serviceAccounts,button.dataset.id);a=action('serviceAccountAction');if(!item)return 'Service account is no longer in the current result set. Refresh before acting.';if(['issue','revoke'].includes(a)&&item.state!=='ACTIVE')return actionStateUnavailable('service account',a,item.state);}
  if(button.dataset.apiTokenAction){actionContractHandled=true;const account=find(state.serviceAccounts,button.dataset.accountId),token=(state.apiTokens?.[button.dataset.accountId]||[]).find(row=>String(row.id)===String(button.dataset.tokenId));a=action('apiTokenAction');if(!account||!token)return 'API token is no longer in the current result set. Refresh before acting.';if(account.state!=='ACTIVE')return actionStateUnavailable('service account',a,account.state,'Token mutation is unavailable after the owning service account is revoked.');const effective=tokenEffectiveState(token);if(effective!=='ACTIVE')return actionStateUnavailable('API token',a,effective);}
  if(button.dataset.notificationDestinationAction){actionContractHandled=true;item=find(state.notificationDestinations,button.dataset.id);a=action('notificationDestinationAction');if(!item)return 'Notification destination is no longer in the current result set. Refresh before acting.';if(['edit','disable'].includes(a)&&item.state!=='ACTIVE')return actionStateUnavailable('notification destination',a,item.state);}
  if(button.dataset.notificationRouteAction){actionContractHandled=true;item=find(state.notificationRoutes,button.dataset.id);if(!item)return 'Notification route is no longer in the current result set. Refresh before acting.';}
  if(button.dataset.gitProviderAction){actionContractHandled=true;item=find(state.gitProviders,button.dataset.id);a=action('gitProviderAction');if(!item)return 'Git provider is no longer in the current authority response. Refresh before acting.';if(a==='rebind'){const select=$(`[data-git-provider-credential="${item.id}"]`),credentialId=String(select?.value||'');if(!credentialId)return 'Select an active Git credential before rebinding the provider.';if(credentialId===String(item.credentialId||''))return 'This provider already uses the selected credential.';const credential=find(state.gitCredentials,credentialId);if(!credential||credential.state!=='ACTIVE')return 'The selected Git credential is no longer ACTIVE. Refresh credential authority before rebinding.';}}
  if(button.dataset.gitCredentialAction){actionContractHandled=true;a=action('gitCredentialAction');const form=$('#git-credential-rotate-form'),credential=find(state.gitCredentials,form?.dataset?.credentialId);if(!credential)return 'Active Git credential authority is unavailable. Refresh before acting.';if(a==='revoke'&&credential.state!=='ACTIVE')return actionStateUnavailable('Git credential','Revoke',credential.state);}
  if(button.dataset.gitLkgRollback){item=find(state.managedGitRevisions,button.dataset.gitLkgRollback);if(!item)return 'Last-known-good revision is no longer in the current result set. Refresh before rollback.';if(!item.lastKnownGood)return 'This revision is no longer marked last-known-good. Refresh before rollback.';const latest=state.managedGitRevisions.filter(row=>row.organization===item.organization&&row.repository===item.repository&&row.branch===item.branch).sort((left,right)=>String(right.updatedAt||right.createdAt||'').localeCompare(String(left.updatedAt||left.createdAt||'')))[0];if(latest&&latest.commitSha===item.commitSha)return 'Desired state already points at this last-known-good commit; rollback would be a no-op.';}
  if(button.dataset.operationCancel){item=find(state.operations,button.dataset.operationCancel);if(!item)return 'Operation is no longer in the current result set. Refresh before acting.';if(['SUCCEEDED','ROLLED_BACK','CANCELLED'].includes(item.state))return actionStateUnavailable('operation','Cancel',item.state);if(item.state==='CANCEL_REQUESTED')return 'Cancellation is already requested. Inspect the operation for safe-boundary progress and evidence.';}
  if(button.dataset.blueprintAction){actionContractHandled=true;item=find(state.blueprintReleases,button.dataset.id);a=action('blueprintAction');if(!item)return 'Blueprint release is no longer in the current result set. Refresh before acting.';const allowed={edit:['DRAFT'],review:['DRAFT'],'request-changes':['REVIEW'],publish:['REVIEW'],clone:['PUBLISHED','DEPRECATED','REVOKED'],deprecate:['PUBLISHED'],revoke:['PUBLISHED','DEPRECATED']};if(allowed[a]&&!allowed[a].includes(item.state))return actionStateUnavailable('Blueprint release',a,item.state);}
  if(button.dataset.catalogAction){actionContractHandled=true;item=find(state.catalogReleases,button.dataset.id);a=action('catalogAction');if(!item)return 'Catalog release is no longer in the current result set. Refresh before acting.';const allowed={refresh:['DRAFT'],review:['DRAFT'],'request-changes':['REVIEW'],publish:['REVIEW'],render:['PUBLISHED'],promote:['PUBLISHED','DEPRECATED'],deprecate:['PUBLISHED'],revoke:['PUBLISHED','DEPRECATED']};if(allowed[a]&&!allowed[a].includes(item.state))return actionStateUnavailable('catalog release',a,item.state);}
  if(button.dataset.gitPrAction){actionContractHandled=true;item=state.gitPullRequests?.find?.(row=>String(row.id)===String(button.dataset.prId));a=action('gitPrAction');if(!item)return 'Pull request is no longer in the current authority response. Refresh before acting.';if(a==='approve'&&item.state!=='OPEN')return actionStateUnavailable('pull request','Approve',item.state);if(a==='merge'&&item.state!=='APPROVED')return actionStateUnavailable('pull request','Merge',item.state);}
  if(button.dataset.clusterAction){actionContractHandled=true;const row=state.clusters.find(value=>String((value.cluster||value).id)===String(button.dataset.id));item=row?.cluster||row;a=action('clusterAction');if(!item)return 'Cluster is no longer in the current result set. Refresh before acting.';if(a==='revoke'&&item.connectionState==='REVOKED')return actionStateUnavailable('cluster agent access','Revoke',item.connectionState);}
  if(button.dataset.agentCertificateAction){actionContractHandled=true;a=action('agentCertificateAction');const certState=String(button.dataset.state||'UNKNOWN');if(a==='revoke'&&certState!=='ACTIVE')return actionStateUnavailable('agent certificate','Revoke',certState);}
  if(button.dataset.maintenanceWindowAction){actionContractHandled=true;item=find(state.clusterMaintenanceWindows,button.dataset.id);a=action('maintenanceWindowAction');if(!item)return 'Maintenance window is no longer in the current result set. Refresh before acting.';if(['run','cancel'].includes(a)&&item.state!=='ACTIVE')return actionStateUnavailable('maintenance window',a,item.state);}
  if(button.dataset.maintenanceRunAction){actionContractHandled=true;item=find(state.clusterMaintenanceRuns,button.dataset.id);a=action('maintenanceRunAction');if(!item)return 'Maintenance run is no longer in the current result set. Refresh before acting.';if(a==='approve'&&item.state!=='AWAITING_APPROVAL')return actionStateUnavailable('maintenance run','Approve',item.state);}
  if(button.dataset.driftAction){actionContractHandled=true;item=find(state.driftScans,button.dataset.scanId);a=action('driftAction');if(!item)return 'Drift scan is no longer in the current result set. Refresh before acting.';const target=(item.targets||[]).find(row=>String(row.clusterId)===String(button.dataset.clusterId));if(!target)return 'Drift target is no longer in the current scan. Refresh before acting.';if(a==='adopt-git'&&!target.git?.adoptable)return 'Trusted Git state is no longer adoptable for this target. Refresh drift evidence before acting.';if(a==='remediate-finding'){const finding=(target.findings||[]).find(row=>String(row.fingerprint)===String(button.dataset.fingerprint));if(!finding)return 'Drift finding is no longer present. Refresh before remediation.';if(finding.remediation?.mode!=='OPERATION'||!finding.remediation?.eligible)return 'This drift finding is no longer eligible for operation-backed remediation.';}}
  if(button.dataset.fleetAction){actionContractHandled=true;item=find(state.fleetGroups,button.dataset.id);a=action('fleetAction');if(!item)return 'Fleet group is no longer in the current result set. Refresh before acting.';if(!Array.isArray(item.clusterIds)||!item.clusterIds.length)return 'Fleet action is unavailable because the group has no bound clusters.';}
  if(button.dataset.workspaceBindingAction){actionContractHandled=true;item=find(state.workspaceBindings,button.dataset.id);a=action('workspaceBindingAction');if(!item)return 'Workspace binding is no longer in the current result set. Refresh before acting.';if(a==='revoke'&&item.state!=='ACTIVE')return actionStateUnavailable('workspace binding','Revoke',item.state);}
  if(button.dataset.virtualClusterAction){actionContractHandled=true;item=find(state.virtualClusters,button.dataset.id);a=action('virtualClusterAction');if(!item)return 'Virtual cluster is no longer in the current result set. Refresh before acting.';if(a==='suspend'&&item.state!=='ACTIVE')return actionStateUnavailable('virtual cluster','Suspend',item.state);if(a==='resume'&&item.state!=='SUSPENDED')return actionStateUnavailable('virtual cluster','Resume',item.state);if(a==='delete'&&!['REQUESTED','ACTIVE','SUSPENDED','FAILED'].includes(item.state))return actionStateUnavailable('virtual cluster','Delete',item.state);}
  if(button.dataset.catalogTrustAction){actionContractHandled=true;item=find(state.catalogTrustKeys,button.dataset.id);a=action('catalogTrustAction');if(!item)return 'Catalog trust key is no longer in the current result set. Refresh before acting.';if(a==='revoke'&&item.state!=='ACTIVE')return actionStateUnavailable('catalog trust key','Revoke',item.state);}
  if(button.dataset.operationAction){actionContractHandled=true;item=find(state.operations,button.dataset.id);a=action('operationAction');if(!item)return 'Operation is no longer in the current result set. Refresh before acting.';if(a==='recover'){if(!['FAILED','CANCEL_REQUESTED'].includes(item.state))return actionStateUnavailable('operation','Start recovery',item.state);if(!item.compensationPlanDigest||!(item.compensationStepCount>0))return 'Recovery is unavailable because this operation has no bound compensation plan.';}}
  if(button.dataset.membershipRevoke){item=state.organizationMemberships.find(row=>String(row.subject)===String(button.dataset.membershipRevoke));if(!item)return 'Organization membership is no longer in the current result set. Refresh before acting.';if(item.state!=='ACTIVE')return actionStateUnavailable('organization membership','Revoke',item.state);}
  if(button.dataset.oidcMappingRevoke){item=find(state.oidcGroupMappings,button.dataset.oidcMappingRevoke);if(!item)return 'OIDC group mapping is no longer in the current result set. Refresh before acting.';if(item.state!=='ACTIVE')return actionStateUnavailable('OIDC group mapping','Revoke',item.state);}
  if(button.dataset.orgEdit){item=find(state.organizations,button.dataset.orgEdit);if(!item)return 'Organization is no longer in the current result set. Refresh before editing.';}
  if(button.dataset.notificationRetryDeadLetter){item=find(state.notificationDeliveries,button.dataset.notificationRetryDeadLetter);if(!item)return 'Notification delivery is no longer in the current result set. Refresh before retrying.';if(item.state!=='DEAD_LETTER')return actionStateUnavailable('notification delivery','Requeue',item.state);}
  const actionEntry=Object.entries(button.dataset).find(([key])=>key.endsWith('Action'));
  if(actionEntry&&statefulMutationActionKeys.has(actionEntry[0])&&!actionContractHandled&&!['inspect','view','timeline','bundle','impact'].includes(String(actionEntry[1]||'').toLowerCase()))return `Action-state contract is unavailable for ${actionEntry[0]}. Refresh before acting.`;
  return '';
}
function scopedMutationReason(button) {
  if(!canOperate())return 'Read-only session';
  if(state.scopeTransitioning)return 'Organization/project scope is changing';
  if(state.session&&!state.scopeReady)return 'Organization/project scope is unavailable; retry before mutating';
  const adminHolder=button.closest('[data-required-global-role="platform-admin"]');
  if(adminHolder&&!canAdminister())return 'platform-admin is required';
  if(!isLocalSession()&&!canAdminister()&&!state.permissionContextReady)return 'Permission scope is temporarily unavailable';
  const projectHolder=button.closest('[data-project-scope]');
  if(projectHolder){
    const projectId=projectHolder.dataset.projectScope;
    if(!projectBelongsToGlobalScope(projectId))return 'Action belongs to a project outside the selected global scope';
    const required=projectHolder.dataset.scopeAccess||'write';
    const role=effectiveProjectRole(projectId);
    if(!scopeRoleAllows(role,required))return required==='admin'?'Project administrator access is required':'Project write access is required';
  }
  const organizationHolder=button.closest('[data-organization-scope]');
  if(organizationHolder){
    const organizationId=organizationHolder.dataset.organizationScope;
    if(!organizationBelongsToGlobalScope(organizationId))return 'Action belongs to an organization outside the selected global scope';
    const required=organizationHolder.dataset.scopeAccess||'write';
    const role=effectiveOrganizationRole(organizationId);
    if(!scopeRoleAllows(role,required))return required==='admin'?'Organization administrator access is required':'Organization write access is required';
  }
  const stateReason=operationalActionStateReason(button);
  if(stateReason)return stateReason;
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
  'closure-baseline','runtime-certification-project','ai-project','template-schema-project','template-policy-project','platform-template-project','recovery-cluster','fleet-project','workspace-authority-project','workspace-binding-workspace','workspace-binding-cluster','tenant-organization','tenant-project',
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

const projectScopedCollectionPaths=new Set([
  '/api/v1/clusters','/api/v1/cluster-imports','/api/v1/provider-profiles','/api/v1/provider-clusters',
  '/api/v1/marketplace/installations','/api/v1/marketplace/recommendations','/api/v1/baseline-deployments',
  '/api/v1/runtime-verifications','/api/v1/runtime-closure-campaigns','/api/v1/runtime-certifications',
  '/api/v1/recovery-checkpoints','/api/v1/fleet-groups','/api/v1/drift-scans','/api/v1/upgrade-campaigns',
  '/api/v1/tenants','/api/v1/ai/runs','/api/v1/workspaces','/api/v1/blueprint-releases',
  '/api/v1/blueprint-overlays','/api/v1/variable-schemas','/api/v1/platform-policy-sets','/api/v1/platform-templates'
]);
const boundedOperatorCollectionLimit=100;
const boundedOperatorCollectionPaths=new Set([
  '/api/v1/clusters','/api/v1/cluster-imports','/api/v1/provider-profiles','/api/v1/provider-clusters',
  '/api/v1/marketplace/installations','/api/v1/marketplace/recommendations','/api/v1/baseline-deployments','/api/v1/runtime-verifications','/api/v1/runtime-closure-campaigns','/api/v1/runtime-certifications',
  '/api/v1/recovery-checkpoints','/api/v1/fleet-groups','/api/v1/drift-scans','/api/v1/upgrade-campaigns',
  '/api/v1/tenants','/api/v1/ai/runs','/api/v1/workspaces','/api/v1/blueprint-releases','/api/v1/platform-templates'
]);
const organizationScopedCollectionPaths=new Set(['/api/v1/service-accounts','/api/v1/notification-destinations']);
const combinedScopedReadPaths=new Set(['/api/v1/control-plane/summary','/api/v1/control-plane/attention','/api/v1/operations','/api/v1/operations/queue-center','/api/v1/logs','/api/v1/audit-events','/api/v1/notification-routes','/api/v1/notification-events','/api/v1/notification-deliveries']);
const organizationFilteredResponsePaths=new Set(['/api/v1/organizations','/api/v1/service-accounts','/api/v1/notification-destinations','/api/v1/catalog-trust-keys','/api/v1/catalog-releases']);

function scopeURL(path) {
  const origin=location.origin&&location.origin!=='null'?location.origin:'http://localhost';
  return new URL(path,origin);
}
function scopedRequestPath(path,method='GET') {
  if(method!=='GET'||!String(path).startsWith('/api/v1/'))return path;
  const url=scopeURL(path),pathname=url.pathname;
  if(boundedOperatorCollectionPaths.has(pathname)&&!url.searchParams.has('limit'))url.searchParams.set('limit',String(boundedOperatorCollectionLimit));
  if(!state.scopeReady)return `${url.pathname}${url.search}${url.hash}`;
  if(combinedScopedReadPaths.has(pathname)){
    if(state.globalScope.organizationId)url.searchParams.set('organizationId',state.globalScope.organizationId);
    if(state.globalScope.projectId)url.searchParams.set('projectId',state.globalScope.projectId);
  }else if(projectScopedCollectionPaths.has(pathname)){
    if(state.globalScope.projectId)url.searchParams.set('projectId',state.globalScope.projectId);
  }else if(organizationScopedCollectionPaths.has(pathname)){
    if(state.globalScope.organizationId)url.searchParams.set('organizationId',state.globalScope.organizationId);
  }else if(pathname==='/api/v1/projects'&&state.globalScope.organizationId){
    url.searchParams.set('organizationId',state.globalScope.organizationId);
  }
  return `${url.pathname}${url.search}${url.hash}`;
}
function scopedRecordProjectID(item) {
  return String(item?.projectId||item?.cluster?.projectId||item?.installation?.projectId||item?.deployment?.projectId||item?.verification?.projectId||item?.campaign?.projectId||item?.tenant?.projectId||item?.profile?.projectId||item?.release?.projectId||'').trim();
}
function scopedRecordOrganizationID(item) {
  return String(item?.organizationId||item?.organization?.id||'').trim();
}
function applyGlobalScopeResponse(path,body,method='GET') {
  if(method!=='GET'||!state.scopeReady||!Array.isArray(body)||(!state.globalScope.organizationId&&!state.globalScope.projectId))return body;
  const pathname=scopeURL(path).pathname;
  if(pathname==='/api/v1/organizations'){
    return state.globalScope.organizationId?body.filter(item=>item.id===state.globalScope.organizationId):body;
  }
  if(pathname==='/api/v1/projects'){
    if(state.globalScope.projectId)return body.filter(item=>item.id===state.globalScope.projectId);
    if(state.globalScope.organizationId)return body.filter(item=>item.organizationId===state.globalScope.organizationId);
    return body;
  }
  if(projectScopedCollectionPaths.has(pathname)){
    return body.filter(item=>projectBelongsToGlobalScope(scopedRecordProjectID(item)));
  }
  if(organizationFilteredResponsePaths.has(pathname)&&state.globalScope.organizationId){
    return body.filter(item=>{
      const organizationId=scopedRecordOrganizationID(item);
      if(pathname==='/api/v1/catalog-releases'&&(item?.visibility==='PLATFORM'||!organizationId))return true;
      if(pathname==='/api/v1/catalog-trust-keys'&&!organizationId)return true;
      return organizationId===state.globalScope.organizationId;
    });
  }
  return body;
}
function globalScopeRequestError(message) {
  const error=new Error(message);error.code='GLOBAL_SCOPE_MISMATCH';error.status=409;return error;
}
function assertGlobalScopeRequest(path,method,bodyObject) {
  if(method!=='GET'&&state.session&&!state.scopeReady)throw globalScopeRequestError('Organization/project scope authority is unavailable. Retry before mutating.');
  if(!state.scopeReady||!String(path).startsWith('/api/v1/'))return;
  const url=scopeURL(path);
  const projectId=String(url.searchParams.get('projectId')||bodyObject?.projectId||'').trim();
  const organizationId=String(url.searchParams.get('organizationId')||bodyObject?.organizationId||'').trim();
  if(projectId&&!projectBelongsToGlobalScope(projectId))throw globalScopeRequestError('Requested project is outside the selected global scope.');
  if(organizationId&&!organizationBelongsToGlobalScope(organizationId))throw globalScopeRequestError('Requested organization is outside the selected global scope.');
  if(method!=='GET'&&state.scopeTransitioning)throw globalScopeRequestError('Organization/project scope is changing. Retry the mutation after the scoped page reloads.');
}

const operationalMutationPathRules=[
  [/\/managed-okd-installs(?:\/|$)/,'clusters'],[/\/maintenance-runs(?:\/|$)/,'clusters'],[/\/provider-clusters(?:\/|$)/,'providers'],[/\/marketplace\/installations(?:\/|$)/,'marketplace'],
  [/\/baseline-deployments(?:\/|$)/,'baselines'],[/\/runtime-verifications(?:\/|$)/,'verification'],[/\/runtime-closure-campaigns(?:\/|$)/,'verification'],
  [/\/runtime-certifications(?:\/|$)/,'verification'],[/\/upgrade-campaigns(?:\/|$)/,'fleet'],[/\/tenants(?:\/|$)/,'tenants'],
  [/\/drift-scans\/.+\/remediate(?:\/|$)/,'fleet'],[/\/operations(?:\/|$)/,'operations']
];
function mutationOutcomeCandidate(path,body) {
  if(!body||typeof body!=='object'||Array.isArray(body))return null;
  const page=operationalMutationPathRules.find(([pattern])=>pattern.test(scopeURL(path).pathname))?.[1];
  if(!page)return null;
  const candidates=[body.install?.operation,body.install,body.operation,body.run,body.providerCluster,body.deployment,body.installation,body.campaign,body.tenant,body.verification,body.certification,body];
  const resource=candidates.find(value=>value&&typeof value==='object'&&(value.id||value.operationId||value.destructiveOperationId));
  if(!resource)return null;
  const operation=body.operation&&typeof body.operation==='object'?body.operation:null;
  return {page,path:scopeURL(path).pathname,id:String(resource.id||operation?.id||''),state:String(resource.state||resource.status||operation?.state||'ACCEPTED'),operationId:String(operation?.id||resource.operationId||resource.destructiveOperationId||''),kind:String(operation?.kind||resource.kind||'operational mutation')};
}
function renderMutationOutcome() {
  const banner=$('#mutation-outcome');if(!banner)return;
  const outcome=state.mutationOutcome;
  if(!outcome){banner.hidden=true;banner.innerHTML='';return;}
  const operationPart=outcome.operationId?` · operation <span class="technical">${esc(outcome.operationId)}</span>`:'';
  banner.hidden=false;
  banner.innerHTML=`<div><strong>Request accepted; terminal success is not implied.</strong><span>${badge(outcome.state)} <span class="technical">${esc(outcome.id||outcome.kind)}</span>${operationPart}</span></div><div class="button-row"><button type="button" class="secondary small-button" id="mutation-outcome-view">${outcome.operationId?'View operation':'View authoritative state'}</button><button type="button" class="quiet small-button" id="mutation-outcome-dismiss">Dismiss</button></div>`;
  banner.querySelector('#mutation-outcome-view').onclick=()=>navigate(outcome.operationId?'operations':outcome.page);
  banner.querySelector('#mutation-outcome-dismiss').onclick=()=>{state.mutationOutcome=null;renderMutationOutcome();};
}
function captureMutationOutcome(path,method,body) {
  if(!['POST','PUT','PATCH','DELETE'].includes(method))return;
  const outcome=mutationOutcomeCandidate(path,body);if(!outcome)return;
  state.mutationOutcome=outcome;renderMutationOutcome();
}
function resourceScopeFamily(path) {
  const pathname=String(path||'').split('?')[0];
  if(!pathname.startsWith('/api/v1/'))return '';
  return pathname.slice('/api/v1/'.length).split('/')[0];
}
function assertResourceScopeKnown(path) {
  const family=resourceScopeFamily(path);if(!family)return;
  const registry=state.resourceScopeRegistry;
  if(!registry||registry.authority!=='RESOURCE_SCOPE_REGISTRY_V1'||!Array.isArray(registry.families)){
    const error=new Error('Resource scope authority is unavailable; retry after session authority refresh.');
    error.code='RESOURCE_SCOPE_AUTHORITY_UNAVAILABLE';error.status=503;throw error;
  }
  const owner=registry.families.find(row=>row.family===family);
  if(!owner||owner.status!=='OWNER_CLASSIFIED'||owner.scope==='UNCLASSIFIED'){
    const error=new Error(`Resource family ${family} is awaiting explicit owner review; the console will not widen its scope.`);
    error.code='RESOURCE_SCOPE_OWNER_REVIEW_REQUIRED';error.status=503;throw error;
  }
}
async function api(path, options = {}) {
  assertResourceScopeKnown(path);
  const request = {...options, headers: {...(options.headers || {})}};
  const method = String(request.method || 'GET').toUpperCase();
  const bodyObject=request.body!==null&&typeof request.body==='object'&&!Array.isArray(request.body)?request.body:null;
  path=scopedRequestPath(path,method);
  assertGlobalScopeRequest(path,method,bodyObject);
  if (method === 'GET' && !request.signal && state.pageLoadController) request.signal = state.pageLoadController.signal;
  const mutation = ['POST','PUT','PATCH','DELETE'].includes(method);
  const submittedForm = mutation && state.lastSubmittedForm && (Date.now()-state.lastSubmittedAt)<500 ? state.lastSubmittedForm : null;
  if (mutation) { state.lastSubmittedForm = null; state.lastSubmittedAt = 0; }
  const viewerSafePost = ['/api/v1/blueprints/validate','/api/v1/blueprints/authoring-roundtrip','/api/v1/blueprints/resolve','/api/v1/plans','/api/v1/compatibility/evaluate','/api/v1/installations/plans','/api/v1/blueprint-releases/compare','/api/v1/runtime-closure-reports/verify','/api/v1/edge/boot-attestations/assess','/api/v1/edge/local-ai/profiles/validate','/api/v1/edge/local-authority/policies/compile','/api/v1/edge/local-authority/mutations/admit','/api/v1/edge/local-authority/reconnect/resolve','/api/v1/support-bundles','/api/v1/support-bundle-jobs','/api/v1/workload-log-queries'].includes(path);
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
  captureMutationOutcome(path,method,body);
  return applyGlobalScopeResponse(path,body,method);
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
function setProjectOptions(select, projects, labelFn = item => `${item.displayName||item.name||item.id} · ${item.name||item.id}`, emptyLabel = 'Create a project first') {
  if(!select)return;
  setOptions(select,projects,item=>item.id,labelFn,emptyLabel);
  const scopedProject=String(state.globalScope.projectId||'').trim();
  if(scopedProject&&projects.some(item=>String(item.id)===scopedProject)){
    select.value=scopedProject;
    select.disabled=true;
    select.dataset.globalScopeBound='true';
  }else{
    delete select.dataset.globalScopeBound;
  }
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


const pageGuidance = {
  overview:{en:['Outcome','Know what is healthy, what is blocked, and the next safe action.','Done when','Attention items have an owner or an explicit next action.'],fa:['خروجی این صفحه','بدانید چه چیزی سالم است، چه چیزی مانع دارد و اقدام امن بعدی چیست.','پایان کار','هر مورد مهم مسئول یا اقدام بعدی مشخص دارد.']},
  workspace:{en:['Outcome','Set organization/project ownership and scoped access.','Done when','People and automation identities have only the intended scope.'],fa:['خروجی این صفحه','مالکیت سازمان/پروژه و دسترسی محدود را تنظیم کنید.','پایان کار','کاربران و هویت‌های خودکار فقط همان دسترسی موردنیاز را دارند.']},
  installation:{en:['Outcome','Produce a validated Platform Factory control-plane install plan.','Done when','Topology, access, integrations, TLS and recovery path are validated before bootstrap.'],fa:['خروجی این صفحه','برای کنترل‌پلین Platform Factory یک برنامه نصب معتبر بسازید.','پایان کار','توپولوژی، دسترسی، سرویس‌ها، TLS و مسیر بازیابی پیش از راه‌اندازی تأیید شده‌اند.']},
  clusters:{en:['Outcome','Create or connect a Kubernetes platform and obtain authoritative inventory.','Done when','The platform is connected and capabilities/inventory are current enough for allowed operations.'],fa:['خروجی این صفحه','یک پلتفرم Kubernetes بسازید یا متصل کنید و موجودی معتبر منابع را بگیرید.','پایان کار','پلتفرم متصل است و موجودی و قابلیت‌های آن برای عملیات مجاز به‌اندازهٔ کافی تازه است.']},
  providers:{en:['Outcome','Verify reusable infrastructure capability and provision a dedicated target.','Done when','The profile is READY and the requested platform has an authoritative lifecycle state.'],fa:['خروجی این صفحه','قابلیت زیرساخت را تأیید کنید و یک مقصد اختصاصی بسازید.','پایان کار','پروفایل آماده است و پلتفرم درخواستی وضعیت معتبر چرخهٔ عمر دارد.']},
  templates:{en:['Outcome','Compose reusable schema, policy and platform template authority.','Done when','A versioned template can be selected without re-entering low-level policy.'],fa:['خروجی این صفحه','طرح داده، سیاست و قالب قابل‌استفادهٔ مجدد بسازید.','پایان کار','قالب نسخه‌دار بدون ورود دوبارهٔ تنظیمات سطح پایین قابل انتخاب است.']},
  blueprints:{en:['Outcome','Publish an immutable platform standard with compatibility and upgrade intent.','Done when','A reviewed release is publishable and its supported upgrade edges are explicit.'],fa:['خروجی این صفحه','استاندارد تغییرناپذیر پلتفرم را همراه با سازگاری و مسیر ارتقا بسازید.','پایان کار','انتشار بررسی‌شده آماده است و مسیرهای ارتقای مجاز صریح هستند.']},
  marketplace:{en:['Outcome','Install a published offer on an eligible connected platform.','Done when','Plan, approval, execution and uninstall/recovery state remain traceable.'],fa:['خروجی این صفحه','یک بسته منتشرشده را روی پلتفرم واجد شرایط نصب کنید.','پایان کار','برنامه، تأیید، اجرا و وضعیت حذف یا بازیابی قابل پیگیری است.']},
  baselines:{en:['Outcome','Apply a certified baseline with a truthful impact preview.','Done when','Only admitted resources changed and completion evidence is sealed.'],fa:['خروجی این صفحه','نسخهٔ پایهٔ تأییدشده را با پیش‌نمایش واقعی اثر تغییر اعمال کنید.','پایان کار','فقط منابع مجاز تغییر کرده‌اند و شواهد پایان کار مهرشده است.']},
  verification:{en:['Outcome','Turn runtime observations into verifiable assurance evidence.','Done when','The verification/certification state is backed by the required evidence.'],fa:['خروجی این صفحه','مشاهدهٔ محیط اجرا را به شواهد قابل‌تأیید تبدیل کنید.','پایان کار','وضعیت بررسی و تأیید فنی با شواهد لازم پشتیبانی می‌شود.']},
  edge:{en:['Outcome','Review bounded site-local authority and disconnected trust without creating a second control plane.','Done when','Policy, boot evidence, reconnect decision and local AI profile are explicit and any runtime mutation remains on the durable operation path.'],fa:['خروجی این صفحه','اختیار محدود محلی و اعتماد در حالت قطع ارتباط را بدون ساخت کنترل‌پلین دوم بررسی کنید.','پایان کار','سیاست، شواهد راه‌اندازی، تصمیم اتصال مجدد و پروفایل هوش مصنوعی محلی روشن است و هر تغییر محیط اجرا از مسیر عملیات پایدار عبور می‌کند.']},
  workspaces:{en:['Outcome','Bind application/team workspaces to the correct namespaces and scope.','Done when','Each workspace binding matches its intended project, cluster and namespace.'],fa:['خروجی این صفحه','فضای کاری تیم یا اپلیکیشن را به Namespace و محدودهٔ درست متصل کنید.','پایان کار','هر اتصال با پروژه، کلاستر و Namespace موردنظر منطبق است.']},
  finops:{en:['Outcome','Review measured usage and publish versioned rates without inventing missing cost.','Done when','Every total is derived from measured telemetry and an immutable rate card, or explicitly marked unavailable.'],fa:['خروجی این صفحه','مصرف اندازه‌گیری‌شده و نرخ‌های نسخه‌دار را بدون ساختن هزینه برای دادهٔ گمشده بررسی کنید.','پایان کار','هر مبلغ از دادهٔ اندازه‌گیری‌شده و نرخ تغییرناپذیر به‌دست آمده یا صریحاً ناموجود اعلام شده است.']},
  fleet:{en:['Outcome','Resolve drift or execute a controlled fleet campaign.','Done when','Each target has an explicit desired/observed state and recovery evidence.'],fa:['خروجی این صفحه','مغایرت را رفع کنید یا کارزار کنترل‌شدهٔ ناوگان را اجرا کنید.','پایان کار','هر مقصد وضعیت مطلوب و مشاهده‌شده و شواهد بازیابی مشخص دارد.']},
  tenants:{en:['Outcome','Create tenant environments with the intended entitlement and branding.','Done when','Namespace lifecycle, plan limits and organization branding agree.'],fa:['خروجی این صفحه','محیط Tenant را با مجوز و برندسازی درست بسازید.','پایان کار','چرخهٔ عمر Namespace، محدودیت برنامه و برندسازی سازمان با هم سازگارند.']},
  operations:{en:['Outcome','Understand what happened, why, and what recovery action is allowed.','Done when','The operation has a terminal or explicitly recoverable state with evidence.'],fa:['خروجی این صفحه','بفهمید چه اتفاقی افتاده، چرا رخ داده و چه اقدام بازیابی مجاز است.','پایان کار','عملیات به وضعیت نهایی یا وضعیت قابل‌بازیابی روشن همراه با شواهد رسیده است.']},
  ai:{en:['Outcome','Get context-bound diagnosis without giving the model direct infrastructure authority.','Done when','Advice cites current product context and any mutation remains a normal approval-bound operation.'],fa:['خروجی این صفحه','تشخیص مبتنی بر وضعیت فعلی بگیرید، بدون اینکه هوش مصنوعی دسترسی مستقیم به زیرساخت داشته باشد.','پایان کار','پیشنهاد بر وضعیت فعلی تکیه دارد و هر تغییر از مسیر عادی عملیات و تأیید می‌گذرد.']},
  lab:{en:['Outcome','Collect exact-SHA physical runtime certification evidence.','Done when','Required matrix cases are executed on the exact artifact and evidence is sealed.'],fa:['خروجی این صفحه','شواهد اجرای فیزیکی را برای همان SHA دقیق جمع‌آوری کنید.','پایان کار','سناریوهای لازم ماتریس روی همان artifact اجرا شده‌اند و شواهد مهرشده‌اند.']},
  notifications:{en:['Outcome','Route the right operational events to the right destinations.','Done when','Preview matches policy and delivery history confirms the intended route.'],fa:['خروجی این صفحه','رویداد عملیاتی درست را به مقصد درست هدایت کنید.','پایان کار','پیش‌نمایش با سیاست منطبق است و سابقهٔ تحویل مسیر موردنظر را تأیید می‌کند.']},
  services:{en:['Outcome','Connect product-owned integrations with explicit credential and revision authority.','Done when','Git/service status shows the expected provider, revision and reconciliation state.'],fa:['خروجی این صفحه','یکپارچه‌سازی‌های محصول را با مرجع اطلاعات دسترسی و بازنگری مشخص متصل کنید.','پایان کار','وضعیت سرویس، ارائه‌دهنده، بازنگری و همگام‌سازی مورد انتظار را نشان می‌دهد.']},
  catalog:{en:['Outcome','Admit a trusted, signed and governed catalog release.','Done when','Upstream source, signature/trust and shipped inventory agree on the release.'],fa:['خروجی این صفحه','انتشار معتبر و امضاشدهٔ کاتالوگ را پس از بررسی سیاست‌ها بپذیرید.','پایان کار','منبع بالادستی، اعتماد به امضا و موجودی همراه محصول همگی همان انتشار را تأیید می‌کنند.']},
  validator:{en:['Outcome','Get a planning result without changing runtime state.','Done when','Compatibility/validation output is clear enough to continue in an executable workflow.'],fa:['خروجی این صفحه','بدون تغییر محیط اجرا، نتیجهٔ برنامه‌ریزی بگیرید.','پایان کار','نتیجهٔ سازگاری و اعتبارسنجی برای ادامه در جریان اجرایی روشن است.']}
};
function renderPageGuidance(){
  const page=$(`#${state.currentPage}`),intro=page?.querySelector(':scope > .section-intro, :scope > .page-heading, :scope > .operator-briefing'),guide=pageGuidance[state.currentPage];if(!page||!intro||!guide)return;
  page.querySelector(':scope > .page-outcome-strip')?.remove();
  const [outcomeLabel,outcome,doneLabel,done]=guide[state.locale==='fa'?'fa':'en'];
  const node=document.createElement('div');node.className='page-outcome-strip';node.setAttribute('role','note');
  node.innerHTML=`<div><span class="page-outcome-label">${esc(outcomeLabel)}</span><strong>${esc(outcome)}</strong></div><div><span class="page-outcome-label">${esc(doneLabel)}</span><span>${esc(done)}</span></div>`;
  intro.insertAdjacentElement('afterend',node);
}

const pageTitles = {
  overview:{en:['Overview','Platform readiness'],fa:['نمای کلی','آمادگی پلتفرم']},
  installation:{en:['Platforms','Control-plane install'],fa:['پلتفرم‌ها','نصب کنترل‌پلین']},clusters:{en:['Platforms','Create & manage platforms'],fa:['پلتفرم‌ها','ایجاد و مدیریت پلتفرم']},providers:{en:['Platforms','Infrastructure profiles'],fa:['پلتفرم‌ها','پروفایل‌های زیرساخت']},
  marketplace:{en:['Blueprints','Marketplace'],fa:['Blueprintها','Marketplace']},blueprints:{en:['Blueprints','Platform blueprints'],fa:['Blueprintها','Blueprintهای پلتفرم']},templates:{en:['Blueprints','Platform templates'],fa:['Blueprintها','قالب‌های پلتفرم']},baselines:{en:['Blueprints','Certified baselines'],fa:['Blueprintها','Baselineهای تأییدشده']},catalog:{en:['Assurance','Supply-chain releases'],fa:['تضمین','انتشارهای زنجیره تأمین']},validator:{en:['Blueprints','Planning tools'],fa:['Blueprintها','ابزارهای برنامه‌ریزی']},
  fleet:{en:['Fleet','Fleet overview'],fa:['Fleet','نمای کلی Fleet']},workspaces:{en:['Fleet','Application workspaces'],fa:['Fleet','فضاهای کاری اپلیکیشن']},finops:{en:['Fleet','FinOps & chargeback'],fa:['Fleet','هزینه و مصرف']},verification:{en:['Assurance','Runtime assurance'],fa:['تضمین','تضمین Runtime']},edge:{en:['Assurance','Edge & sovereign'],fa:['تضمین','Edge و حاکمیت محلی']},
  operations:{en:['Operations','Activity & audit'],fa:['عملیات','فعالیت و ممیزی']},ai:{en:['Operations','AI Operator'],fa:['عملیات','اپراتور هوش مصنوعی']},lab:{en:['Assurance','Physical certification'],fa:['تضمین','گواهی فیزیکی']},notifications:{en:['Operations','Notifications'],fa:['عملیات','اعلان‌ها']},
  workspace:{en:['Admin','Organizations & projects'],fa:['مدیریت','سازمان‌ها و پروژه‌ها']},tenants:{en:['Admin','Tenant environments & branding'],fa:['مدیریت','محیط‌های Tenantها و برندینگ']},services:{en:['Admin','Integrations & services'],fa:['مدیریت','یکپارچه‌سازی و سرویس‌ها']}
};
const sectionNavigation = {
  home:['overview'],
  infrastructure:['clusters','providers','installation'],
  delivery:['blueprints','templates','marketplace','baselines','validator'],
  fleet:['fleet','workspaces','finops'],
  operations:['operations','ai','notifications'],
  assurance:['verification','edge','catalog','lab'],
  administration:['workspace','tenants','services']
};
const sectionLabels = {
  home:{en:'Overview',fa:'نمای کلی'}, infrastructure:{en:'Platforms',fa:'پلتفرم‌ها'}, delivery:{en:'Blueprints',fa:'Blueprintها'}, fleet:{en:'Fleet',fa:'Fleet'}, operations:{en:'Operations',fa:'عملیات'}, assurance:{en:'Assurance',fa:'تضمین'}, administration:{en:'Admin',fa:'مدیریت'}
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
  renderPageGuidance();
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
$('#global-organization-scope').addEventListener('change',async event=>{
  await changeGlobalScope(event.target.value,'');
});
$('#global-project-scope').addEventListener('change',async event=>{
  const projectId=event.target.value;
  const project=scopeDirectoryProject(projectId);
  await changeGlobalScope(project?.organizationId||state.globalScope.organizationId,projectId);
});
$('#language-toggle').onclick = async () => {
  if(hasUnsavedChanges()&&!await confirmAction('Discard unsaved changes?', 'Changing the console language refreshes this page and will discard unsaved form changes.', true))return;
  clearDirtyForms();state.locale = state.locale === 'fa' ? 'en' : 'fa'; localStorage.setItem('platformLocale', state.locale); applyLocale(); renderGlobalScope(); await loadPage(state.currentPage);
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
        const [context,resourceScopes]=await Promise.all([authorityJSON('/api/v1/access/context'),authorityJSON('/api/v1/access/resource-scopes')]);
        state.accessContext=isPermissionContext(context)?context:null;
        state.resourceScopeRegistry=resourceScopes?.authority==='RESOURCE_SCOPE_REGISTRY_V1'&&Array.isArray(resourceScopes?.families)?resourceScopes:null;
        state.permissionContextReady=!!state.accessContext&&!!state.resourceScopeRegistry;
      }catch(scopeError){
        if(scopeError?.status===401)throw scopeError;
        state.accessContext=null;
        state.resourceScopeRegistry=null;
        state.permissionContextReady=false;
      }
      await refreshGlobalScopeDirectory();
      const label = state.session.name || state.session.email || state.session.sub || 'Signed in';
      const role = isLocalSession() ? 'local admin' : (sessionRoles().find(item => ['platform-admin','platform-operator','platform-viewer'].includes(item)) || 'read only');
      $('#session-state').textContent = `${label} · ${role}${state.permissionContextReady||canAdminister()?'':' · permission scope unavailable'}`;
      invalidateDestructiveConfirmationOnDemotion(previousCanOperate);
      applyAccessMode();
      return state.permissionContextReady||canAdminister();
    } catch (error) {
      state.session = null;
      state.accessContext = null;
      state.resourceScopeRegistry = null;
      state.permissionContextReady=false;
      state.scopeReady=false;
      renderGlobalScope();
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
  const [version, summary, attention, operations, audit] = await Promise.all([
    api('/api/v1/version'),
    softApi('/api/v1/control-plane/summary',{},'control-plane summary'),
    softApi('/api/v1/control-plane/attention?limit=9',[],'operator attention'),
    softApi('/api/v1/operations?limit=20',[],'operations'),
    softApi('/api/v1/audit-events?limit=20',[],'audit')
  ]);
  Object.assign(state, {version, summary, attention, operations, audit});
  $('#release-version').textContent=version.version||'unknown';
}

function latest(items) { return [...items].sort((a,b) => new Date(b.updatedAt || b.createdAt || 0) - new Date(a.updatedAt || a.createdAt || 0)); }
function operationLabel(operation) { return operation.kind || 'operation'; }

async function loadOverview() {
  try {
    await loadCore();
    const failureSources=['operator attention'];
    const summaryUnavailable=sourceUnavailable('control-plane summary');
    const summary=state.summary||{};
    const connected=Number(summary.connectedClusters||0), managed=Number(summary.managedClusters||0), failed=Number(summary.failedProductWorkflows||0);
    $('#overview-metrics').innerHTML = [
      ['Organizations', summaryUnavailable?'—':Number(summary.organizations||0), summaryUnavailable?'Summary authority unavailable':`${Number(summary.projects||0)} projects`],
      ['Connected clusters', summaryUnavailable?'—':connected, summaryUnavailable?'Summary authority unavailable':`${Math.max(0,managed-connected)} offline or pending`],
      ['Successful baselines', summaryUnavailable?'—':Number(summary.successfulBaselineDeployments||0), summaryUnavailable?'Summary authority unavailable':`${Number(summary.baselineDeployments||0)} total deployments`],
      ['Needs attention', summaryUnavailable?'—':failed, summaryUnavailable?'Summary authority unavailable':(failed ? 'Open failed product workflows' : 'No failed product workflow')]
    ].map(([label,value,detail]) => `<article class="metric-card"><strong>${esc(value)}</strong><span>${esc(label)}</span><small>${esc(detail)}</small></article>`).join('');

    const readinessCheck=(done,title,detail,page)=>({unknown:summaryUnavailable,done:!summaryUnavailable&&done,title,detail,page});
    const checks = [
      readinessCheck(Number(summary.organizations||0)>0,'Create an organization','Ownership boundary for projects and entitlements','workspace'),
      readinessCheck(Number(summary.projects||0)>0,'Create a project','Resource and operation isolation boundary','workspace'),
      readinessCheck(Number(summary.managedClusters||0)>0,'Connect a Kubernetes cluster','Outbound agent enrollment and fresh inventory','clusters'),
      readinessCheck(Number(summary.successfulBaselineDeployments||0)>0,'Apply the certified baseline','Explicit plan review and approval','baselines'),
      readinessCheck(Number(summary.successfulRuntimeVerifications||0)>0,'Verify runtime health','Digest-pinned probe and report','verification'),
      readinessCheck(Number(summary.successfulRuntimeClosureCampaigns||0)>0,'Close runtime evidence','Bind inventory, baseline and verification digests','verification')
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

    const attentionPartial=sourceUnavailable(failureSources);
    const attention=(state.attention||[]).map(item=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">!</span><div><strong>${esc(item.displayName||item.id)}</strong><small>${esc(item.message||'Operator attention is required.')}</small></div></div><div class="activity-actions">${badge(item.state)}${item.page?`<button type="button" class="link-button small-button" data-navigate="${esc(item.page)}">Open</button>`:''}</div></div>`);
    $('#attention-list').innerHTML = attention.length ? `${attentionPartial?'<div class="warning-banner"><strong>Attention is partial.</strong> The bounded attention authority is temporarily unavailable.</div>':''}${attention.join('')}` : attentionPartial ? unavailableState('Attention data') : emptyState('No urgent action', 'No failed workflow or offline connected cluster is currently reported.');

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
  const scope=[body.organizationId?`organization ${body.organizationId} as ${body.organizationRole}`:'',body.projectId?`project ${body.projectId} as ${body.projectRole}`:''].filter(Boolean).join(' · ')||'no delegated organization/project role';if(!await confirmAction('Create OIDC group mapping',`Map ${body.group} to product role ${body.productRole}; ${scope}. New OIDC requests carrying this group can gain the mapped access immediately.`))return;
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
  try { const existing=state.organizationMemberships.find(item=>item.subject===subject),role=$('#membership-role').value;if(existing&&existing.state==='ACTIVE'&&existing.role===role){toast('Organization membership already has the selected role.','error');return;}const impact=existing?`Change ${subject} from ${existing.role} to ${role}? This changes effective organization access immediately.`:`Grant ${role} organization access to ${subject}?`;if(!await confirmAction(existing?'Change organization access':'Grant organization access',impact,Boolean(existing)))return;const headers=existing?{'If-Match':`"${existing.revision}"`}:{'If-None-Match':'*'}; await api(`/api/v1/organizations/${encodeURIComponent(orgId)}/memberships/${encodeURIComponent(subject)}`,{method:'PUT',headers,body:{role}}); $('#membership-subject').value=''; toast('Organization access updated.'); await loadWorkspace(); }
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
    if(action==='issue'){const options=apiTokenPermissionProfiles(account);const values=await askFields('Issue API token',[{name:'hours',label:'Expires in hours',type:'number',value:24,min:1,max:8784},{name:'permission',label:'Permission profile',type:'select',options}], 'Review token');if(!values)return;if(!await confirmAction('Issue API token',`Issue a one-time ${values.permission} token for ${account.displayName} that expires in ${values.hours} hour(s)? The plaintext token is shown only once.`))return;try{const response=await api(`/api/v1/service-accounts/${account.id}/tokens`,{method:'POST',headers:{'Idempotency-Key':idempotency('api-token-issue')},body:{expiresAt:new Date(Date.now()+Number(values.hours)*3600000).toISOString(),permissions:apiTokenPermissionsFromProfile(values.permission)}});showOneTimeAPIToken('API token issued',response);await loadServiceAccounts($('#service-account-organization').value);}catch(error){toast(error.message,'error');}return;}
    if(action==='revoke'){if(!await confirmAction('Revoke service account',`Revoke ${account.displayName} and immediately invalidate every active token?`,true))return;try{await api(`/api/v1/service-accounts/${account.id}/revoke`,{method:'POST',headers:{'If-Match':`"${account.revision}"`,'X-Confirm-Revoke':'revoke-service-account'}});toast('Service account revoked.');await loadServiceAccounts($('#service-account-organization').value);}catch(error){toast(error.message,'error');}return;}
  }
  const tokenButton=event.target.closest('[data-api-token-action]');if(!tokenButton)return;const account=state.serviceAccounts.find(item=>item.id===tokenButton.dataset.accountId);const token=(state.apiTokens[tokenButton.dataset.accountId]||[]).find(item=>item.id===tokenButton.dataset.tokenId);if(!account||!token)return;
  if(tokenButton.dataset.apiTokenAction==='revoke'){if(!await confirmAction('Revoke API token',`Immediately revoke ${token.tokenPrefix}?`,true))return;try{await api(`/api/v1/service-accounts/${account.id}/tokens/${token.id}/revoke`,{method:'POST',headers:{'If-Match':`"${token.revision}"`,'X-Confirm-Revoke':'revoke-api-token'}});toast('API token revoked.');await loadServiceAccounts($('#service-account-organization').value);}catch(error){toast(error.message,'error');}return;}
  const options=apiTokenPermissionProfiles(account);const values=await askFields('Rotate API token',[{name:'hours',label:'New expiry in hours',type:'number',value:24,min:1,max:8784},{name:'permission',label:'Permission profile',type:'select',options,value:apiTokenPermissionProfileValue(token.permissions)}],'Review rotation');if(!values)return;if(!await confirmAction('Rotate API token',`Rotate ${token.tokenPrefix}? The current token is invalidated and the replacement ${values.permission} token is shown only once.`,true))return;
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
const installationFieldLabels={url:'HTTPS endpoint',credentialRef:'Credential reference',organization:'Organization',repository:'Repository',webhookMode:'Webhook mode',region:'Region',bucket:'مخزن S3',prefix:'پیشوند مسیر',issuerUrl:'OIDC issuer URL',clientId:'OIDC client ID',adminEmail:'Bootstrap administrator email'};
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
    const sizing=profile.sizing||{},minimum=(sizing.minimumVcpu||sizing.minimumMemoryGiB||sizing.minimumDiskGiB)?`${esc(sizing.minimumVcpu||0)} vCPU / ${esc(sizing.minimumMemoryGiB||0)} GiB RAM / ${esc(sizing.minimumDiskGiB||0)} GiB disk`:'';
    const recommended=(sizing.recommendedVcpu||sizing.recommendedMemoryGiB||sizing.recommendedDiskGiB)?`${esc(sizing.recommendedVcpu||0)} vCPU / ${esc(sizing.recommendedMemoryGiB||0)} GiB RAM / ${esc(sizing.recommendedDiskGiB||0)} GiB disk`:'';
    $('#installation-profile-summary').innerHTML = `<strong>${esc(profile.displayName)}</strong><br>${esc(profile.description)}<br>Required nodes: ${profile.minNodes}${profile.recommendedNodes !== profile.minNodes ? ` · recommended ${profile.recommendedNodes}` : ''} · ${profile.production ? 'production' : 'evaluation'}${minimum?`<br><span class="field-label">Sizing baseline</span> ${minimum}${recommended?` · recommended ${recommended}`:''} <span class="technical">${esc(sizing.status||'')}</span>`:''}`;
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
function renderInstallerRecoveryCenter(){
  const target=$('#installer-recovery-authority'),model=state.installationRecoveryAuthority||{};if(!target)return;
  if(!model.authority){target.innerHTML=emptyState('Recovery authority unavailable','The standalone Installer Recovery Console authority could not be loaded.');return;}
  const actions=(model.actions||[]).map(action=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">↳</span><div><strong>${esc(action.category)} · ${esc(action.id)}</strong><small class="technical">${esc(action.method)} ${esc(action.path)} · ${esc(action.description)}</small></div></div><div class="resource-meta">${badge(action.risk||'UNKNOWN')}${action.confirmation?badge('CONFIRMATION'):''}</div></div>`).join('');
  target.innerHTML=`<div class="resource-details">${detailRow('Authority',model.authority,true)}${detailRow('Bootstrap plane',model.separateBootstrapPlane?'SEPARATE / SURVIVES API OUTAGE':'UNKNOWN')}${detailRow('Credential boundary',model.credentialBoundary||'—')}</div><details><summary>Recovery capabilities · ${(model.actions||[]).length}</summary><div class="activity-list">${actions}</div></details>`;
}
$('#installer-recovery-open').onclick=()=>{const raw=$('#installer-recovery-url').value.trim();if(!raw){toast('Enter the Installer Recovery Console URL.','error');return;}try{const url=new URL(raw);if(!['https:','http:'].includes(url.protocol))throw new Error('Only HTTP(S) URLs are allowed.');window.open(url.toString(),'_blank','noopener,noreferrer');}catch(error){toast(error.message||'Invalid Installer URL.','error');}};

async function loadInstallation() {
  try {
    const [profiles,integrations,recoveryAuthority]=await Promise.all([softApi('/api/v1/installations/profiles',[],'installation profiles'),softApi('/api/v1/installations/integrations',{},'installation integrations'),softApi('/api/v1/installations/recovery-authority',{},'installer recovery authority')]);
    state.profiles = profiles; state.installationIntegrations=integrations; state.installationRecoveryAuthority=recoveryAuthority;
    renderInstallerRecoveryCenter();
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
    state.clusterMaintenanceProfile=null; state.clusterMaintenanceWindows=[]; state.clusterMaintenanceRuns=[]; state.targetNodeLifecycleAuthority=null; state.currentMaintenanceClusterId='';
    $('#maintenance-authority-summary').textContent='Connect a cluster first.';
    $('#maintenance-window-grid').innerHTML=emptyState('No maintenance windows','Connect a cluster and configure its environment profile first.');
    $('#maintenance-run-grid').innerHTML=emptyState('No maintenance runs','Create a bounded maintenance window first.');
    $('#target-node-lifecycle-grid').innerHTML=emptyState('No node lifecycle authority','Connect a cluster with current inventory first.');
    return;
  }
  let profile=null;
  try { profile=(await api(`/api/v1/clusters/${clusterId}/maintenance-profile`)).profile; } catch(error) { if(error.status!==404) throw error; }
  const clusterRecord=state.clusters.find(row=>(row.cluster||row).id===clusterId),clusterResource=clusterRecord?.cluster||clusterRecord||{},maintenanceProjectId=clusterResource.projectId||'';
  const [windowResult,runResult,day2CampaignEngine,nodeLifecycleAuthority,providerClusters]=await Promise.all([softApi(`/api/v1/clusters/${clusterId}/maintenance-windows`,[],'maintenance windows'),softApi(`/api/v1/clusters/${clusterId}/maintenance-runs`,[],'maintenance runs'),softApi('/api/v1/day2-campaign-engine',{},'Day-2 campaign engine'),softApi(`/api/v1/clusters/${clusterId}/node-lifecycle-authority`,{actions:[]},'target node lifecycle authority'),maintenanceProjectId?softApi(`/api/v1/provider-clusters?projectId=${encodeURIComponent(maintenanceProjectId)}`,[],'provider clusters'):Promise.resolve([])]);
  if(generation!==state.maintenanceLoadGeneration)return false;
  const profileForm=$('#maintenance-profile-form'),windowForm=$('#maintenance-window-form');
  const profileDirty=dirtyWithin(profileForm),windowDirty=dirtyWithin(windowForm);
  state.clusterMaintenanceProfile=profile; state.clusterMaintenanceWindows=windowResult.windows||[]; state.clusterMaintenanceRuns=runResult.runs||[]; state.targetNodeLifecycleAuthority=nodeLifecycleAuthority?.authority?nodeLifecycleAuthority:null; state.day2CampaignEngine=day2CampaignEngine?.authority?day2CampaignEngine:state.day2CampaignEngine; state.providerClusters=providerClusters||[]; state.currentMaintenanceClusterId=clusterId;
  if(!profileDirty){$('#maintenance-environment').value=profile?.environment||'DEVELOPMENT';$('#maintenance-default-timeout').value=profile?.defaultDrainTimeoutSeconds||300;markFormClean(profileForm);}
  if(!windowDirty){$('#maintenance-window-timeout').value=profile?.defaultDrainTimeoutSeconds||300;markFormClean(windowForm);}
  $('#maintenance-authority-summary').innerHTML=profile?`<strong>${esc(profile.environment)}</strong> · default drain ${esc(profile.defaultDrainTimeoutSeconds)}s · ${esc(state.clusterMaintenanceWindows.filter(w=>w.state==='ACTIVE').length)} active window(s) · inventory-bound approval · maxUnavailable=1`:'<strong>Profile required.</strong> Set the environment and default drain timeout before opening a maintenance window.';
  setIntrinsicDisabled($('#maintenance-window-form').querySelector('button[type="submit"]'), !profile);
  const lifecycleActions=state.targetNodeLifecycleAuthority?.actions||[];
  $('#target-node-lifecycle-grid').innerHTML=lifecycleActions.length?lifecycleActions.map(item=>{const add=item.action==='ADD',providerMutation=['REMOVE','REPLACE','CERTIFICATE_RENEWAL','REMEDIATE'].includes(item.action),bindingReady=Boolean(state.targetNodeLifecycleAuthority?.providerBindingReady),bindingId=state.targetNodeLifecycleAuthority?.providerClusterId||'—',bindButton=add&&!bindingReady&&canAdminister()?`<button type="button" class="secondary small-button" data-node-lifecycle-bind="ADD">Bind provider</button>`:'',executeLabel=add?'Request Add':item.action==='REMOVE'?'Request Remove':item.action==='REPLACE'?'Request Replace':item.action==='CERTIFICATE_RENEWAL'?'Request Certificate Renewal':item.action==='REMEDIATE'?'Request Remediation':'',executeButton=(add||providerMutation)&&item.executable&&canAdminister()?`<button type="button" class="primary small-button" data-node-lifecycle-execute="${esc(item.action)}">${executeLabel}</button>`:'';return `<article class="resource-card"><div class="resource-header"><div><h3>${esc(String(item.action||'').replaceAll('_',' '))}</h3><div class="resource-meta">${badge(item.executable?'EXECUTABLE':'BLOCKED')}${badge(item.executor||'unknown')}</div></div></div><div class="resource-details">${(add||providerMutation)?detailRow('Provider binding',bindingReady?bindingId:'Not bound',true):''}${detailRow('Required capabilities',(item.requiredCapabilities||[]).join(', ')||'—',true)}${detailRow('Missing capabilities',(item.missingCapabilities||[]).join(', ')||'—',true)}${detailRow('Development blockers',(item.blockers||[]).join(', ')||'—',true)}${detailRow('Physical certification',state.targetNodeLifecycleAuthority.physicalCertificationStatus||'DEFERRED_UNTIL_DEVELOPMENT_CLOSURE',true)}</div><div class="resource-actions"><button type="button" class="secondary small-button" data-node-lifecycle-plan="${esc(item.action)}">Preview impact</button>${bindButton}${executeButton}</div></article>`}).join(''):emptyState('No node lifecycle authority','Current inventory cannot provide node lifecycle planning authority.');
  $('#maintenance-window-grid').innerHTML=state.clusterMaintenanceWindows.length?latest(state.clusterMaintenanceWindows).map(window=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(window.name)}</h3><div class="resource-meta">${badge(window.state)}${badge('maxUnavailable=1')}</div></div></div><div class="resource-details">${detailRow('Starts',formatDate(window.startsAt))}${detailRow('Ends',formatDate(window.endsAt))}${detailRow('Drain timeout',`${window.drainTimeoutSeconds}s`)}${detailRow('Created by',window.createdBy||'—')}${detailRow('Revision',window.revision)}</div><div class="resource-actions">${window.state==='ACTIVE'?`<button type="button" class="primary small-button" data-maintenance-window-action="run" data-id="${esc(window.id)}">Maintain node</button><button type="button" class="danger small-button" data-maintenance-window-action="cancel" data-id="${esc(window.id)}">Cancel window</button>`:''}</div></article>`).join(''):emptyState('No maintenance windows','Configure the environment profile, then create a bounded maintenance window.');
  $('#maintenance-run-grid').innerHTML=state.clusterMaintenanceRuns.length?latest(state.clusterMaintenanceRuns).map(run=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc((run.nodeNames||[]).join(', '))}</h3><div class="resource-meta">${badge(run.state)}${badge(run.action||'DRAIN')}${run.maxUnavailable?badge(`maxUnavailable=${run.maxUnavailable}`):''}</div></div></div><div class="resource-details">${detailRow('Operation',run.operationId||'—',true)}${detailRow('وضعیت ثبت‌شده',shortDigest(run.inventoryDigest))}${detailRow('Window',run.windowId||'—',true)}${detailRow('Action',run.action||'DRAIN')}${detailRow('Requested by',run.requestedBy||'—')}${detailRow('Approved by',run.approvedBy||'—')}${detailRow('Error',run.lastError||'—')}</div>${(run.results||[]).length?`<details><summary>Node results</summary><div class="activity-list">${run.results.map(row=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">${row.unCordoned||row.uncordoned?'✓':'!'}</span><div><strong class="technical">${esc(row.nodeName)}</strong><small>Cordon ${row.cordoned?'PASS':'NO'} · Drain ${row.drained?'PASS':'NO'} · Uncordon ${row.uncordoned?'PASS':'NO'} · evicted ${(row.evictedPods||[]).length} · PDB waits ${(row.pdbBlockedPods||[]).length}${run.action==='OS_PATCH'?` · Host patch ${row.hostActionSucceeded?'PASS':'NO'} · Reboot ${row.rebootRequired?'REQUIRED':'NO'}`:''}</small></div></div></div>`).join('')}</div></details>`:''}<div class="resource-actions">${run.state==='AWAITING_APPROVAL'?approvalControl(run,'Approve maintenance',`data-maintenance-run-action="approve" data-id="${esc(run.id)}" data-revision="${run.revision}"`):''}<button type="button" class="secondary small-button" data-maintenance-run-action="inspect" data-id="${esc(run.id)}">Inspect</button></div></article>`).join(''):emptyState('No maintenance runs','Start maintenance from an active window. Approval is required before the agent can claim work.');
  return true;
}


function managedOKDStage(stage){
  $$('[data-managed-okd-stage]').forEach(section=>{section.hidden=Number(section.dataset.managedOkdStage)!==Number(stage);});
  const current=$(`[data-managed-okd-stage="${stage}"]`);current?.querySelector('input,select,textarea')?.focus({preventScroll:true});
}
function syncManagedOKDConnectivity(){
  const mode=$('#managed-okd-connectivity')?.value||'connected',disconnected=mode==='disconnected',fields=$('#managed-okd-disconnected-fields');
  if(fields){fields.hidden=!disconnected;$$('input',fields).forEach(input=>input.required=disconnected);}
  const runtime=state.managedOKDRuntime||{},allowed=disconnected?Boolean(runtime.disconnectedRequestAllowed):Boolean(runtime.connectedRequestAllowed??runtime.requestCreationAllowed);
  const submit=$('#managed-okd-submit');if(submit)setIntrinsicDisabled(submit,(state.projects||[]).length===0||!allowed);
  const status=$('#managed-okd-runtime-status');
  if(status){
    const connected=Boolean(runtime.connectedRequestAllowed??runtime.requestCreationAllowed),disc=Boolean(runtime.disconnectedRequestAllowed);
    status.classList.toggle('warning-banner',!allowed);
    if(disconnected&&!disc)status.innerHTML=`<strong>${esc(t('managedOkd.runtimeDisconnectedUnavailable','Connected execution is ready, but the disconnected path does not have an exact oc-mirror v2 runtime.'))}</strong>`;
    else if(allowed)status.innerHTML=`<strong>${esc(t('managedOkd.runtimeReady','Managed OKD execution is ready. Requests enter execution only after independent approval.'))}</strong>`;
    else status.innerHTML=`<strong>${esc(t('managedOkd.runtimeUnavailable','Managed OKD execution is not configured on this control plane. Configure the exact runtime/workspace first; request submission is disabled.'))}</strong>`;
    if(connected&&!disc&&!disconnected)status.innerHTML+=`<br><span>${esc(t('managedOkd.runtimeDisconnectedUnavailable','Connected execution is ready, but the disconnected path does not have an exact oc-mirror v2 runtime.'))}</span>`;
  }
}
$('#managed-okd-connectivity').onchange=syncManagedOKDConnectivity;

function managedOKDStageValid(stage){
  const current=$(`[data-managed-okd-stage="${stage}"]`);if(!current)return false;
  for(const control of $$('input,select,textarea',current)){if(!control.checkValidity()){control.reportValidity();control.focus();return false;}}
  if(Number(stage)===1&&$('#managed-okd-api-vip').value.trim()===$('#managed-okd-ingress-vip').value.trim()){toast('API VIP and Ingress VIP must be different.','error');$('#managed-okd-ingress-vip').focus();return false;}
  return true;
}
function canonicalSHA256Input(value){const digest=String(value||'').trim().toLowerCase();return /^[0-9a-f]{64}$/.test(digest)?`sha256:${digest}`:digest;}
$$('[data-platform-path]').forEach(button=>button.onclick=async()=>{
  const path=button.dataset.platformPath;
  if(path==='provider'){await navigate('providers');return;}
  const details=path==='okd'?$('#managed-okd-console'):$('#cluster-import-console');if(details){details.open=true;details.scrollIntoView({behavior:'smooth',block:'start'});setTimeout(()=>details.querySelector('input,select,button')?.focus(),180);}
});
$$('[data-managed-okd-next]').forEach(button=>button.onclick=()=>{const stage=Number(button.closest('[data-managed-okd-stage]')?.dataset.managedOkdStage||0);if(managedOKDStageValid(stage))managedOKDStage(Number(button.dataset.managedOkdNext));});
$$('[data-managed-okd-back]').forEach(button=>button.onclick=()=>managedOKDStage(Number(button.dataset.managedOkdBack)));
$('#managed-okd-copy-paths').onclick=()=>{const system=$('#managed-okd-node-1-system').value.trim(),media=$('#managed-okd-node-1-media').value.trim();if(!system||!media){toast('Enter node 1 System and VirtualMedia resource paths first.','error');return;}for(let i=2;i<=3;i++){ $(`#managed-okd-node-${i}-system`).value=system;$(`#managed-okd-node-${i}-media`).value=media; }toast('Only Redfish resource paths were copied to nodes 2 and 3.');};
$('#managed-okd-form').onsubmit=async event=>{
  event.preventDefault();
  const connectivity=$('#managed-okd-connectivity').value||'connected';
  const runtimeAllowed=connectivity==='disconnected'?Boolean(state.managedOKDRuntime?.disconnectedRequestAllowed):Boolean(state.managedOKDRuntime?.connectedRequestAllowed??state.managedOKDRuntime?.requestCreationAllowed);
  if(!runtimeAllowed){toast(connectivity==='disconnected'?t('managedOkd.runtimeDisconnectedUnavailable','Disconnected Managed OKD execution is not configured on this control plane.'):t('managedOkd.runtimeUnavailable','Managed OKD execution is not configured on this control plane.'),'error');return;}
  if(!managedOKDStageValid(3))return;
  // The final submit validates all earlier stages too, so programmatic or resumed navigation cannot bypass prerequisites.
  if(!managedOKDStageValid(1)){managedOKDStage(1);return;}
  if(!managedOKDStageValid(2)){managedOKDStage(2);return;}
  const project=state.projects.find(item=>item.id===$('#managed-okd-project').value);if(!project?.organizationId){toast('The selected project has no authoritative organization scope.','error');return;}
  const targetVersion=$('#managed-okd-version').value.trim();
  const machines=[1,2,3].map(i=>({id:$(`#managed-okd-node-${i}-id`).value.trim(),endpoint:$(`#managed-okd-node-${i}-endpoint`).value.trim(),credentialRef:$(`#managed-okd-node-${i}-credential`).value.trim(),systemResource:$(`#managed-okd-node-${i}-system`).value.trim(),virtualMediaResource:$(`#managed-okd-node-${i}-media`).value.trim()}));
  const payload={organizationId:project.organizationId,projectId:project.id,targetVersion,clusterName:$('#managed-okd-name').value.trim(),baseDomain:$('#managed-okd-base-domain').value.trim(),apiVip:$('#managed-okd-api-vip').value.trim(),ingressVip:$('#managed-okd-ingress-vip').value.trim(),connectivity,machines,artifacts:[
    {name:'release-payload',version:targetVersion,url:$('#managed-okd-release-url').value.trim(),sha256:canonicalSHA256Input($('#managed-okd-release-sha').value)},
    {name:'fcos',version:$('#managed-okd-fcos-version').value.trim(),url:$('#managed-okd-fcos-url').value.trim(),sha256:canonicalSHA256Input($('#managed-okd-fcos-sha').value)},
    {name:'agent-iso',version:targetVersion,url:$('#managed-okd-agent-url').value.trim(),sha256:canonicalSHA256Input($('#managed-okd-agent-sha').value)}
  ]};
  if(connectivity==='disconnected')payload.disconnected={mirrorRegistry:$('#managed-okd-mirror-registry').value.trim().toLowerCase().replace(/^\/+|\/+$/g,''),imageSetConfigurationSha256:canonicalSHA256Input($('#managed-okd-imageset-sha').value),mirrorInventorySha256:canonicalSHA256Input($('#managed-okd-inventory-sha').value)};
  try{
    const result=await api('/api/v1/managed-okd-installs',{method:'POST',headers:{'Idempotency-Key':idempotency('managed-okd-install')},body:payload});
    const install=result.install||{},op=install.operation||{};const outcome=$('#managed-okd-result');outcome.hidden=false;outcome.innerHTML=`<strong>Request sealed and awaiting independent approval.</strong><br><span class="technical">${esc(op.id||'operation pending')}</span> · ${badge(op.state||'AWAITING_APPROVAL')} · target ${esc(install.clusterName||payload.clusterName)}<div class="button-row"><button type="button" class="secondary small-button" data-managed-okd-open-operations>Open Operations</button></div>`;outcome.querySelector('[data-managed-okd-open-operations]').onclick=()=>navigate('operations');
    event.currentTarget.reset();managedOKDStage(1);syncManagedOKDConnectivity();toast('Managed OKD install request created; installation success is not implied.');
  }catch(error){toast(error.message,'error');}
};

async function loadClusters() {
  try {
    const [projects, imports, clusters, managedOKDRuntime] = await Promise.all([softApi('/api/v1/projects',[],'projects'), softApi('/api/v1/cluster-imports',[],'cluster imports'), softApi('/api/v1/clusters',[],'clusters'), softApi('/api/v1/managed-okd-installs/runtime',{configured:false,requestCreationAllowed:false,connectedRequestAllowed:false,disconnectedRequestAllowed:false},'managed OKD runtime')]);
    Object.assign(state, {projects, imports, clusters, managedOKDRuntime});
    const connected=clusters.map(row=>row.cluster||row);
    setOptions($('#maintenance-cluster-select'), connected, item=>item.id, item=>`${item.displayName} · ${item.kubernetesVersion||'inventory pending'}`, 'Connect a cluster first');
    setProjectOptions($('#cluster-project'),projects);
    setProjectOptions($('#managed-okd-project'),projects);
    prerequisite($('#clusters-prerequisite'), projects.length > 0, 'A project is required before a cluster can be connected.', 'workspace', 'Create organization and project');
    setIntrinsicDisabled($('#cluster-import-form').querySelector('button[type="submit"]'), projects.length === 0);
    syncManagedOKDConnectivity();
    const clusterRows=clusters.map(row => {
      const cluster=row.cluster||row,inventory=row.inventory||{},readyNodes=(inventory.nodes||[]).filter(node=>node.ready).length,totalNodes=(inventory.nodes||[]).length;
      const actions=`<div class="row-actions"><button type="button" class="secondary small-button" data-cluster-action="inspect" data-id="${esc(cluster.id)}">Details</button>${canAdminister()&&cluster.connectionState!=='REVOKED'?`<button type="button" class="danger small-button" data-cluster-action="revoke" data-id="${esc(cluster.id)}">Revoke</button>`:''}</div>`;
      return tableRow([
        tableCell(`<span class="cell-title">${esc(cluster.displayName)}</span><span class="cell-meta technical">${esc(cluster.id)}</span>`),
        tableCell(`${badge(row.online?'ONLINE':'OFFLINE')} ${badge(cluster.connectionState||'connected')}`,'status-cell'),
        tableCell(`<span class="cell-title">${esc(row.target?.distributionIdentity||cluster.distribution||'Pending')} ${row.okdImportAdmitted?badge('OKD ADMITTED'):''}</span><span class="cell-meta technical">${esc(row.target?.provisioningMode||'import-existing')} · ${esc(cluster.kubernetesVersion||'version pending')}</span>`),
        tableCell(totalNodes?`${esc(readyNodes)}/${esc(totalNodes)} ready`:'وضعیت ثبت‌شده pending','numeric'),
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
$('#target-node-lifecycle-grid').onclick=async event=>{const clusterId=$('#maintenance-cluster-select').value;if(!clusterId)return;const record=state.clusters.find(row=>(row.cluster||row).id===clusterId),cluster=record?.cluster||record,nodes=(record?.inventory?.nodes||[]);const bindButton=event.target.closest('[data-node-lifecycle-bind]');if(bindButton){const candidates=(state.providerClusters||[]).filter(item=>item.projectId===cluster?.projectId&&item.state==='ACTIVE');if(!candidates.length){toast('No ACTIVE provider cluster is available for this target project.','error');return;}const values=await askFields('Bind target to provider cluster',[{name:'providerClusterId',label:'Provider cluster',type:'select',value:candidates[0].id,options:candidates.map(item=>({value:item.id,label:`${item.displayName} · workers ${item.desired?.workerReplicas||0}`}))}],'Bind provider');if(!values)return;if(!await confirmAction('Bind provider cluster',`Bind ${cluster?.displayName||clusterId} to the selected provider cluster? This binding becomes the authoritative lifecycle owner for provider-backed node Add.`))return;try{await api(`/api/v1/clusters/${clusterId}/provider-binding`,{method:'POST',headers:{'If-Match':`"${cluster.revision}"`},body:{providerClusterId:values.providerClusterId}});toast('Provider binding saved.');await loadClusters();}catch(error){toast(error.message,'error');}return;}const executeButton=event.target.closest('[data-node-lifecycle-execute]');if(executeButton){const action=executeButton.dataset.nodeLifecycleExecute;if(action==='ADD'){if(!await confirmAction('Request provider-backed node Add','Increase the bound Cluster API worker topology by one replica? A separate provider-cluster approval is required before execution.'))return;try{const result=await api(`/api/v1/clusters/${clusterId}/node-lifecycle-actions`,{method:'POST',headers:{'Idempotency-Key':idempotency('target-node-add')},body:{action:'ADD'}});toast(result.idempotentReplay?'Existing node Add request reused.':'Node Add requested and waiting for independent provider approval.');await Promise.all([loadClusterMaintenanceAuthority(clusterId),loadProviders()]);}catch(error){toast(error.message,'error');}return;}if(!['REMOVE','REPLACE','CERTIFICATE_RENEWAL','REMEDIATE'].includes(action))return;const workerOnly=nodes.filter(n=>(n.roles||[]).some(role=>String(role).toLowerCase()==='worker')&&!(n.roles||[]).some(role=>['control-plane','controlplane','master','server'].includes(String(role).toLowerCase()))),workerCandidates=action==='REMEDIATE'?workerOnly.filter(n=>!n.ready):workerOnly.filter(n=>n.ready);if(!workerCandidates.length){toast(action==='REMEDIATE'?'No Not Ready worker-only node is available for remediation.':'No Ready worker-only node is available for provider lifecycle execution.','error');return;}const now=Date.now(),windows=(state.clusterMaintenanceWindows||[]).filter(item=>item.state==='ACTIVE'&&new Date(item.startsAt).getTime()<=now&&new Date(item.endsAt).getTime()>now);if(!windows.length){toast('No active maintenance window is available for destructive node lifecycle execution.','error');return;}const title=action==='REMOVE'?'Request provider-backed node Remove':action==='REPLACE'?'Request provider-backed node Replace':action==='CERTIFICATE_RENEWAL'?'Request provider-backed Certificate Renewal':'Request provider-backed Node Remediation',buttonLabel=action==='REMOVE'?'Request Remove':action==='REPLACE'?'Request Replace':action==='CERTIFICATE_RENEWAL'?'Request Certificate Renewal':'Request Remediation';const values=await askFields(title,[{name:'nodeName',label:action==='REMEDIATE'?'Not Ready worker node':'Ready worker node',type:'select',value:workerCandidates[0].name,options:workerCandidates.map(n=>({value:n.name,label:`${n.name} · ${n.uid||'UID unavailable'}`}))},{name:'windowId',label:'Active maintenance window',type:'select',value:windows[0].id,options:windows.map(item=>({value:item.id,label:`${item.name} · ${formatDate(item.endsAt)}`}))}],buttonLabel);if(!values)return;const destructive=action==='REMOVE'||action==='REMEDIATE',message=action==='REMOVE'?`Remove ${values.nodeName} and decrease the bound Cluster API worker topology by exactly one replica? Independent approval is required.`:action==='REPLACE'?`Delete the exact CAPI Machine for ${values.nodeName} so its MachineDeployment creates a replacement? Independent approval is required.`:action==='CERTIFICATE_RENEWAL'?`Replace the exact CAPI Machine for ${values.nodeName} one-for-one so the joining RKE2 worker receives fresh node identity and certificates? Independent approval is required.`:`Remediate unhealthy worker ${values.nodeName} by replacing its exact CAPI Machine one-for-one? Independent approval is required.`;if(!await confirmAction(title,message,destructive))return;try{const result=await api(`/api/v1/clusters/${clusterId}/node-lifecycle-actions`,{method:'POST',headers:{'Idempotency-Key':idempotency(`target-node-${action.toLowerCase()}-${values.nodeName}`)},body:{action,nodeName:values.nodeName,windowId:values.windowId}});const requested=action==='REMOVE'?'Node Remove':action==='REPLACE'?'Node Replace':action==='CERTIFICATE_RENEWAL'?'Certificate Renewal':'Node Remediation';toast(result.idempotentReplay?'Existing provider node lifecycle request reused.':`${requested} requested and waiting for independent provider approval.`);await Promise.all([loadClusterMaintenanceAuthority(clusterId),loadProviders()]);}catch(error){toast(error.message,'error');}return;}const button=event.target.closest('[data-node-lifecycle-plan]');if(!button)return;const action=button.dataset.nodeLifecyclePlan,descriptor=(state.targetNodeLifecycleAuthority?.actions||[]).find(row=>row.action===action);if(!descriptor)return;let nodeName='';if(descriptor.requiresNode){if(!nodes.length){toast('Current inventory has no nodes for lifecycle planning.','error');return;}const values=await askFields('Preview node lifecycle impact',[{name:'nodeName',label:'وضعیت ثبت‌شده node',type:'select',value:nodes[0].name,options:nodes.map(n=>({value:n.name,label:`${n.name} · ${n.ready?'Ready':'Not Ready'} · ${(n.roles||[]).join(', ')||'worker'}`}))}],'Preview impact');if(!values)return;nodeName=values.nodeName;}try{const plan=await api(`/api/v1/clusters/${clusterId}/node-lifecycle-plans`,{method:'POST',body:{action,nodeName}});showDetails('Target node lifecycle plan',`<dl class="key-value"><dt>Authority</dt><dd class="technical">${esc(plan.authority)} · ${esc(plan.campaignAuthority)}</dd><dt>Action</dt><dd>${badge(plan.action)} ${badge(plan.executable?'EXECUTABLE':'BLOCKED')}</dd><dt>اجراکننده</dt><dd class="technical">${esc(plan.executor)}</dd><dt>Provider binding</dt><dd class="technical">${esc(plan.providerClusterId||'—')} · ${plan.providerBindingReady?'READY':'NOT READY'}</dd><dt>Node</dt><dd class="technical">${esc(plan.nodeName||'—')} ${plan.nodeUid?`· ${esc(plan.nodeUid)}`:''}</dd><dt>وضعیت ثبت‌شده</dt><dd class="technical">${esc(plan.inventoryDigest)}</dd><dt>Plan digest</dt><dd class="technical">${esc(plan.planDigest)}</dd><dt>Impact</dt><dd>${esc((plan.impact||[]).join(' · '))}</dd><dt>Recovery</dt><dd>${esc((plan.recovery||[]).join(' · '))}</dd><dt>Development blockers</dt><dd class="technical">${esc((plan.blockers||[]).join(', ')||'—')}</dd><dt>Physical certification</dt><dd class="technical">${esc(plan.physicalCertificationStatus)}</dd></dl>`);}catch(error){toast(error.message,'error');}};
$('#maintenance-window-grid').onclick=async event=>{const button=event.target.closest('[data-maintenance-window-action]');if(!button)return;const clusterId=$('#maintenance-cluster-select').value,window=state.clusterMaintenanceWindows.find(row=>row.id===button.dataset.id);if(!window)return;if(button.dataset.maintenanceWindowAction==='cancel'){if(!await confirmAction('Cancel maintenance window',`Cancel ${window.name}? Existing active runs must finish first.`,true))return;try{await api(`/api/v1/clusters/${clusterId}/maintenance-windows/${window.id}/cancel`,{method:'POST',headers:{'If-Match':`"${window.revision}"`},body:{}});toast('Maintenance window cancelled.');await loadClusterMaintenanceAuthority(clusterId);}catch(error){toast(error.message,'error');}return;}const record=state.clusters.find(row=>(row.cluster||row).id===clusterId),ready=(record?.inventory?.nodes||[]).filter(n=>n.ready);if(!ready.length){toast('Current inventory has no Ready nodes.','error');return;}const executable=(state.targetNodeLifecycleAuthority?.actions||[]).filter(row=>row.executable&&['DRAIN','OS_PATCH'].includes(row.action));if(!executable.length){toast('No executable node maintenance action is admitted by current inventory.','error');return;}const actionOptions=executable.map(row=>({value:row.action,label:row.action==='OS_PATCH'?'OS patch (drain → patch → uncordon)':'Drain workloads'}));const values=await askFields('Run node maintenance',[{name:'action',label:'Node action',type:'select',value:actionOptions[0].value,options:actionOptions},{name:'nodeName',label:'Ready node',type:'select',value:ready[0].name,options:ready.map(n=>({value:n.name,label:`${n.name} · ${(n.roles||[]).join(', ')||'worker'}`}))}],'Request approval');if(!values)return;try{await api(`/api/v1/clusters/${clusterId}/maintenance-runs`,{method:'POST',headers:{'Idempotency-Key':idempotency('cluster-maintenance')},body:{windowId:window.id,action:values.action,nodeNames:[values.nodeName]}});toast(values.action==='OS_PATCH'?'OS patch run created and waiting for independent approval.':'Maintenance run created and waiting for independent approval.');await loadClusterMaintenanceAuthority(clusterId);}catch(error){toast(error.message,'error');}};
$('#maintenance-run-grid').onclick=async event=>{const button=event.target.closest('[data-maintenance-run-action]');if(!button)return;const clusterId=$('#maintenance-cluster-select').value,run=state.clusterMaintenanceRuns.find(row=>row.id===button.dataset.id);if(!run)return;if(button.dataset.maintenanceRunAction==='inspect'){try{const record=await api(`/api/v1/clusters/${clusterId}/maintenance-runs/${run.id}`);showDetails('Cluster maintenance run',`<dl class="key-value"><dt>Authority</dt><dd class="technical">${esc(state.day2CampaignEngine?.authority||'GENERALIZED_DAY2_CAMPAIGN_ENGINE_V1')} · KUBERNETES_NODE_MAINTENANCE_V1</dd><dt>State</dt><dd>${badge(record.run.state)} ${badge(record.run.action||'DRAIN')}</dd><dt>Nodes</dt><dd class="technical">${esc((record.run.nodeNames||[]).join(', '))}</dd><dt>Inventory digest</dt><dd class="technical">${esc(record.run.inventoryDigest)}</dd><dt>Window</dt><dd class="technical">${esc(record.run.windowId)}</dd><dt>Operation</dt><dd class="technical">${esc(record.run.operationId)}</dd><dt>Drain timeout</dt><dd>${esc(record.run.drainTimeoutSeconds)}s</dd><dt>Host action timeout</dt><dd>${record.run.hostActionTimeoutSeconds?`${esc(record.run.hostActionTimeoutSeconds)}s`:'—'}</dd><dt>Error</dt><dd>${esc(record.run.lastError||'—')}</dd></dl>`);}catch(error){toast(error.message,'error');}return;}if(!await confirmAction('Approve node maintenance',run.action==='OS_PATCH'?`Approve cordon, PDB-aware drain, host OS patch and uncordon for ${(run.nodeNames||[]).join(', ')}? Reboot is never automatic.`:`Approve cordon, PDB-aware drain and uncordon for ${(run.nodeNames||[]).join(', ')}?`))return;try{await api(`/api/v1/clusters/${clusterId}/maintenance-runs/${run.id}/approve`,{method:'POST',headers:{'If-Match':`"${run.revision}"`},body:{}});toast('Maintenance approved and queued for the cluster agent.');await loadClusterMaintenanceAuthority(clusterId);}catch(error){toast(error.message,'error');}};

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
      const [record,workloadExplorer] = await Promise.all([api(`/api/v1/clusters/${cluster.id}`),api(`/api/v1/clusters/${cluster.id}/workloads`).catch(error=>({authority:'WORKLOAD_EXPLORER_READ_AUTHORITY_V1',complete:false,stale:true,error:error.message,workloads:[],services:[],ingresses:[],persistentVolumeClaims:[],events:[]}))]);
      const current = record.cluster || cluster, currentInventory = record.inventory || inventory, certificates = record.agentCertificates || [];
      const certificateRows = certificates.length ? `<div class="activity-list">${certificates.map(cert=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">${cert.state==='ACTIVE'?'✓':'×'}</span><div><strong class="technical">${esc(cert.fingerprint)}</strong><small>${esc(cert.serialNumber)} · expires ${formatDate(cert.notAfter)}</small></div></div><div class="resource-actions">${badge(cert.state)}${canAdminister()&&cert.state==='ACTIVE'?`<button type="button" class="danger small-button" data-agent-certificate-action="revoke" data-id="${esc(cert.id)}" data-revision="${cert.revision}" data-state="${esc(cert.state)}">Revoke certificate</button>`:''}</div></div>`).join('')}</div>` : '<p>No client certificate has been issued yet. The bootstrap credential is only used to obtain the first certificate.</p>';
      const reconnect=record.reconnect||{},okdHealth=record.okdHealth||{},targetProfile=record.targetProfile||{},isOKD=(record.target?.distributionIdentity||current.distribution)==='okd';
      const reconnectSection=`<div class="detail-section"><h3>Reconnect authority</h3><div class="resource-details">${detailRow('Status',reconnect.status||'UNKNOWN')}${detailRow('Automatic reconnect',reconnect.automatic?'Yes':'No')}${detailRow('Same cluster identity required',reconnect.sameClusterIdentityRequired?'Yes':'No')}${detailRow('Target RBAC fence required',reconnect.targetRbacFenceRequired?'Yes':'No')}</div><p>${esc(reconnect.next||'Reconnect authority is unavailable.')}</p></div>`;
      const okdSection=isOKD?`<div class="detail-section"><h3>OKD health & profile</h3><div class="resource-meta">${badge(okdHealth.status||'BLOCKED')}${record.okdImportAdmitted?badge('IMPORT ADMITTED'):badge('READ ONLY')}${badge(targetProfile.status||'BLOCKED')}</div><div class="resource-details">${detailRow('Health authority',okdHealth.authority||'—',true)}${detailRow('Cluster version',okdHealth.clusterVersion||current.kubernetesVersion||'—',true)}${detailRow('ClusterOperators',okdHealth.operatorCount||0)}${detailRow('Unavailable',(okdHealth.unavailable||[]).join(', ')||'None')}${detailRow('Progressing',(okdHealth.progressing||[]).join(', ')||'None')}${detailRow('Degraded',(okdHealth.degraded||[]).join(', ')||'None')}${detailRow('Upgrade blocked',(okdHealth.upgradeBlocked||[]).join(', ')||'None')}${detailRow('Profile compiler',targetProfile.authority||'—',true)}</div>${(targetProfile.blockers||[]).length?`<div class="warning-banner">Profile blocked: ${esc(targetProfile.blockers.join(' · '))}</div>`:''}<details><summary>Desired / observed component decisions</summary><div class="activity-list">${(targetProfile.resolution?.decisions||[]).map(item=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">${item.action==='suppress'?'−':item.action==='include'?'+':'!'}</span><div><strong>${esc(item.component)}</strong><small>${esc(item.domain)} · ${esc(item.reason)}</small></div></div>${badge((item.action||'unknown').toUpperCase())}</div>`).join('')||'<p>No profile decisions available.</p>'}</div></details></div>`:'';
      const authorityActions=`<div class="detail-section"><h3>Target authority actions</h3><p>Mutation access is issued only after fresh identity, health and desired/observed profile admission. Revoked clusters must remove any target-side mutation bindings before the same physical UID can re-enroll.</p><div class="resource-actions">${record.mutationRBACActivationRequired&&canAdminister()?`<button type="button" class="primary small-button" data-cluster-authority-action="activate">Issue mutation access manifest</button>`:''}${record.mutationRBACProofPending?'<span class="badge warning">WAITING FOR TARGET PROOF</span>':''}${reconnect.status==='REENROLLMENT_REQUIRED'&&reconnect.targetRbacFenceRequired&&canAdminister()?`<button type="button" class="danger small-button" data-cluster-authority-action="revocation-fence">Target RBAC cleanup</button>`:''}${reconnect.status==='REENROLLMENT_REQUIRED'&&!reconnect.targetRbacFenceRequired?'<span class="badge neutral">READY FOR NEW ENROLLMENT</span>':''}</div></div>`;
      const workloadRows=(workloadExplorer.workloads||[]).slice(0,50).map(item=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">${item.failed>0?'!':item.readyReplicas>=item.desiredReplicas?'✓':'○'}</span><div><strong>${esc(item.kind)} · <span class="technical">${esc(item.namespace)}/${esc(item.name)}</span></strong><small>Ready ${esc(item.readyReplicas||0)}/${esc(item.desiredReplicas||0)}${(item.images||[]).length?` · ${esc((item.images||[]).join(', '))}`:''}</small></div></div>${badge(item.failed>0?'FAILED':item.readyReplicas>=item.desiredReplicas?'READY':'PARTIAL')}</div>`).join('');
      const workloadSection=`<div class="detail-section" data-authority="WORKLOAD_EXPLORER_READ_AUTHORITY_V1"><h3>Workload Explorer</h3><p>Live observational inventory from the managed-cluster Agent. It is bounded and never becomes desired state.</p><div class="resource-meta">${badge(workloadExplorer.fresh?'FRESH':'STALE')}${badge(workloadExplorer.complete?'COMPLETE':'INCOMPLETE')}${workloadExplorer.truncated?badge('TRUNCATED'):''}</div><div class="resource-details">${detailRow('Authority',workloadExplorer.authority||'WORKLOAD_EXPLORER_READ_AUTHORITY_V1',true)}${detailRow('Workloads',(workloadExplorer.workloads||[]).length)}${detailRow('Services',(workloadExplorer.services||[]).length)}${detailRow('Ingresses',(workloadExplorer.ingresses||[]).length)}${detailRow('PVCs',(workloadExplorer.persistentVolumeClaims||[]).length)}${detailRow('Events',(workloadExplorer.events||[]).length)}${detailRow('وضعیت ثبت‌شده',shortDigest(workloadExplorer.inventoryDigest||current.inventoryDigest||''))}</div>${workloadExplorer.error?`<div class="warning-banner">${esc(workloadExplorer.error)}</div>`:''}${workloadRows?`<details open><summary>Controllers (${(workloadExplorer.workloads||[]).length})</summary><div class="activity-list">${workloadRows}</div></details>`:'<p>No controller inventory reported.</p>'}<details><summary>Networking & storage</summary><div class="activity-list">${(workloadExplorer.services||[]).slice(0,30).map(item=>`<div class="activity-item"><div><strong>Service · <span class="technical">${esc(item.namespace)}/${esc(item.name)}</span></strong><small>${esc(item.type||'')} · ${esc((item.ports||[]).map(port=>`${port.port}/${port.protocol||'TCP'}`).join(', ')||'no ports')}</small></div></div>`).join('')}${(workloadExplorer.ingresses||[]).slice(0,30).map(item=>`<div class="activity-item"><div><strong>Ingress · <span class="technical">${esc(item.namespace)}/${esc(item.name)}</span></strong><small>${esc((item.hosts||[]).join(', ')||'no host')}</small></div></div>`).join('')}${(workloadExplorer.persistentVolumeClaims||[]).slice(0,30).map(item=>`<div class="activity-item"><div><strong>PVC · <span class="technical">${esc(item.namespace)}/${esc(item.name)}</span></strong><small>${esc(item.phase||'')} · ${esc(item.requested||'')}</small></div></div>`).join('')||'<p>No Service, Ingress or PVC observations.</p>'}</div></details><details><summary>Recent events (${(workloadExplorer.events||[]).length})</summary><div class="activity-list">${(workloadExplorer.events||[]).slice(0,50).map(item=>`<div class="activity-item"><div><strong>${esc(item.type||'Event')} · ${esc(item.reason||'')}</strong><small><span class="technical">${esc(item.namespace||'')}/${esc(item.regardingKind||'')}/${esc(item.regardingName||'')}</span> · ${esc(item.message||'')}</small></div>${badge(item.count||1)}</div>`).join('')||'<p>No recent events.</p>'}</div></details></div>`;
      showDetails(current.displayName, `<div class="detail-section"><h3>Connection</h3><dl class="key-value"><dt>ID</dt><dd class="technical">${esc(current.id)}</dd><dt>State</dt><dd>${badge(record.online ? 'ONLINE':'OFFLINE')}</dd><dt>Connection authority</dt><dd>${badge(current.connectionState || 'CONNECTED')}</dd><dt>Agent authentication</dt><dd>${badge(record.agentAuthentication || 'bootstrap-bearer')}</dd><dt>Distribution identity</dt><dd>${esc(record.target?.distributionIdentity || current.distribution || '—')}</dd><dt>Provisioning mode</dt><dd>${esc(record.target?.provisioningMode || 'import-existing')}</dd><dt>Infrastructure</dt><dd>${esc(record.target?.infrastructureProvider || 'existing')}</dd><dt>Observed legacy distribution</dt><dd>${esc(record.target?.legacyDistribution || current.distribution || '—')}</dd><dt>Kubernetes</dt><dd class="technical">${esc(current.kubernetesVersion || '—')}</dd><dt>Agent</dt><dd class="technical">${esc(current.agentVersion || '—')}</dd><dt>Last seen</dt><dd>${formatDate(current.lastSeenAt)}</dd></dl></div>${reconnectSection}${okdSection}${authorityActions}${workloadSection}<div class="detail-section"><h3>Agent mTLS certificates</h3><p>Private keys stay on the managed cluster. The control plane stores certificate metadata and revocation state only.</p>${certificateRows}</div><div class="detail-section"><h3>Nodes</h3>${(currentInventory.nodes||[]).length ? `<div class="activity-list">${currentInventory.nodes.map(node=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">${node.ready?'✓':'!'}</span><div><strong class="technical">${esc(node.name)}</strong><small>${esc((node.roles||[]).join(', ') || 'worker')} · ${esc(node.os || '')} ${esc(node.architecture || '')}</small></div></div>${badge(node.ready?'READY':'NOT READY')}</div>`).join('')}</div>` : '<p>No node inventory reported.</p>'}</div><div class="detail-section"><h3>API / CRD discovery</h3><div class="resource-details">${detailRow('API discovery',currentInventory.apiDiscoveryComplete?'Complete':'Incomplete')}${detailRow('API resources',(currentInventory.apiResources||[]).length)}${detailRow('CRD discovery',currentInventory.crdDiscoveryComplete?'Complete':'Incomplete')}${detailRow('CRDs',(currentInventory.crds||[]).length)}</div>${!currentInventory.apiDiscoveryComplete||!currentInventory.crdDiscoveryComplete?'<div class="warning-banner">Planning impact cannot be approval-ready until API and CRD discovery evidence is complete.</div>':''}<details><summary>Discovered API resources</summary><pre class="code-block technical" dir="ltr">${esc((currentInventory.apiResources||[]).map(item=>`${item.apiVersion} ${item.kind} (${item.resource})`).join('\n')||'No API resource inventory')}</pre></details><details><summary>Discovered CRDs</summary><pre class="code-block technical" dir="ltr">${esc((currentInventory.crds||[]).map(item=>`${item.name} · ${(item.versions||[]).filter(v=>v.served).map(v=>v.name).join(', ')}`).join('\n')||'No CRD inventory')}</pre></details></div><div class="detail-section"><h3>Capabilities</h3><div class="resource-meta">${(current.capabilities||[]).map(cap=>`<span class="badge neutral">${esc(cap)}</span>`).join('') || 'None reported'}</div></div>`);
      const authorityButton=$('[data-cluster-authority-action]', $('#detail-content'));
      if(authorityButton)authorityButton.onclick=async()=>{
        if(authorityButton.dataset.clusterAuthorityAction==='activate'){
          if(!await confirmAction('Issue target mutation access',`Issue digest-bound mutation RBAC for ${current.displayName}? Apply the returned manifest on the same cluster; mutation stays blocked until the Agent proves the exact binding.`))return;
          try{const result=await api(`/api/v1/clusters/${current.id}/mutation-rbac-manifest`,{method:'POST',body:{}});showDetails('Apply target mutation access',`<div class="warning-banner">This does not grant mutation until the target applies the exact manifest and the next inventory proves the binding.</div><pre class="code-block technical" dir="ltr">${esc(result.manifest||'')}</pre><div class="resource-details">${detailRow('وضعیت ثبت‌شده digest',result.inventoryDigest||'—',true)}${detailRow('Activation basis',result.activationIssuedForDigest||'—',true)}</div>`);}catch(error){toast(error.message,'error');}
          return;
        }
        if(authorityButton.dataset.clusterAuthorityAction==='revocation-fence'){
          try{const result=await api(`/api/v1/clusters/${current.id}/revocation-rbac-manifest`);showDetails('Target RBAC cleanup',`<div class="warning-banner">Apply this cleanup manifest on the revoked target before acknowledging. The acknowledgement is an operator assertion, not Physical Runtime proof.</div><pre class="code-block technical" dir="ltr">${esc(result.manifest||'')}</pre><div class="resource-details">${detailRow('Fence digest',result.targetRBACRevocationFenceDigest||'—',true)}</div><div class="resource-actions"><button type="button" class="danger small-button" data-cluster-authority-action="ack-revocation">Acknowledge applied cleanup</button></div>`);const ack=$('[data-cluster-authority-action="ack-revocation"]', $('#detail-content'));if(ack)ack.onclick=async()=>{if(!await confirmAction('Acknowledge target RBAC cleanup','Confirm only after the exact cleanup manifest was applied to the revoked target. This enables same-UID re-enrollment but is not Physical certification.',true))return;try{await api(`/api/v1/clusters/${current.id}/revocation-rbac-acknowledgement`,{method:'POST',headers:{'If-Match':`"${current.revision}"`},body:{fenceDigest:result.targetRBACRevocationFenceDigest}});$('#detail-dialog').close();toast('Target RBAC cleanup acknowledged. Same-UID re-enrollment is allowed.');await loadClusters();}catch(error){toast(error.message,'error');}};}catch(error){toast(error.message,'error');}
        }
      };
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
  const search=model?.searchProjection||{};
  const trackCount=(roadmap.tracks||[]).length;
  const positioning=roadmap.positioning||'';
  const differentiators=roadmap.competitiveDifferentiators||[];
  target.innerHTML=`<strong>Target architecture</strong> · admitted <span class="technical">${esc(admitted.join(', ')||'none')}</span>${previews.length?` · preview only <span class="technical">${esc(previews.join(', '))}</span>`:''} · capability resolver <span class="technical">${esc(resolver.authority||'unavailable')}</span>${search.authority?` · search projection <span class="technical">${esc(search.defaultBackend||'none')}</span> ${badge(search.status||'UNKNOWN')}`:''}${current?` · current product phase <strong>${esc(current.id)}</strong>`:''}${trackCount?` · <strong>${esc(trackCount)}</strong> cross-cutting product tracks`:''}${positioning?`<br><span class="field-label">Product position</span> ${esc(positioning)}`:''}${differentiators.length?`<br><span class="field-label">Competitive center</span> ${differentiators.slice(0,3).map(item=>`<span class="badge neutral">${esc(item)}</span>`).join(' ')}`:''}`;
  const field=$('#provider-distributions');if(field&&admitted.length)field.placeholder=admitted.join(',');
}

async function loadProviders() {
  try {
    const [projects, clusterRows, profiles, providerClusters, recoveryCheckpoints, targetArchitecture] = await Promise.all([softApi('/api/v1/projects',[],'projects'),softApi('/api/v1/clusters',[],'clusters'),softApi('/api/v1/provider-profiles',[],'provider profiles'),softApi('/api/v1/provider-clusters',[],'provider clusters'),softApi('/api/v1/recovery-checkpoints',[],'recovery checkpoints'),softApi('/api/v1/target-architecture-model',{},'target architecture')]);
    Object.assign(state,{projects,clusters:clusterRows,providerProfiles:profiles,providerClusters,recoveryCheckpoints,targetArchitecture});
    renderTargetArchitectureSummary(targetArchitecture);
    setProjectOptions($('#provider-project'),projects);
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
function syncProviderInfrastructureFields(){
  const provider=$('#provider-infrastructure-provider').value;
  const managed=['vmware','aws','azure','gcp'].includes(provider);
  const vmware=provider==='vmware';
  $('#provider-managed-fields').hidden=!managed;
  $('#provider-infrastructure-endpoint').required=vmware;
  $('#provider-infrastructure-endpoint').disabled=managed&&!vmware;
  $('#provider-credential-ref').required=managed;
  $('#provider-architectures').readOnly=managed;
  if(managed) $('#provider-architectures').value='amd64';
  if(!vmware) $('#provider-infrastructure-endpoint').value='';
  if(managed) $('#provider-credential-ref').placeholder=`external-secret://4so-provider-system/${provider}-prod`;
  if(!managed){$('#provider-infrastructure-endpoint').value='';$('#provider-credential-ref').value='';$('#provider-credential-ref').placeholder='external-secret://4so-provider-system/provider-prod';}
}
$('#provider-infrastructure-provider').onchange=syncProviderInfrastructureFields;
syncProviderInfrastructureFields();
$('#provider-project').onchange=loadProviders;
$('#provider-profile-select').onchange=()=>{const profile=state.providerProfiles.find(item=>item.id===$('#provider-profile-select').value);if(!profile)return;setOptions($('#provider-cluster-architecture'),profile.architectures||[],item=>item,item=>item,'No admitted architecture');setOptions($('#provider-cluster-distribution'),profile.distributionIdentities||profile.distributionProfiles||[],item=>item,item=>item,'No admitted distribution identity');$('#provider-cluster-version').value=profile.defaultKubernetesVersion||$('#provider-cluster-version').value;};
$('#provider-profile-form').onsubmit=async event=>{
  event.preventDefault(); if(!event.currentTarget.reportValidity())return;
  const payload={projectId:$('#provider-project').value,managementClusterId:$('#provider-management-cluster').value,name:$('#provider-profile-name').value.trim(),displayName:$('#provider-profile-display-name').value.trim(),clusterClassName:$('#provider-cluster-class').value.trim(),workerClassName:$('#provider-worker-class').value.trim(),defaultKubernetesVersion:$('#provider-default-version').value.trim(),kubernetesSeries:$('#provider-series').value.split(',').map(v=>v.trim()).filter(Boolean),architectures:$('#provider-architectures').value.split(',').map(v=>v.trim().toLowerCase()).filter(Boolean),distributionProfiles:$('#provider-distributions').value.split(',').map(v=>v.trim().toLowerCase()).filter(Boolean),infrastructureProvider:$('#provider-infrastructure-provider').value,infrastructureEndpoint:$('#provider-infrastructure-endpoint').value.trim(),credentialRef:$('#provider-credential-ref').value.trim(),maxWorkerReplicas:Number($('#provider-max-workers').value)};
  try{await api('/api/v1/provider-profiles',{method:'POST',headers:{'Idempotency-Key':idempotency('provider-profile')},body:payload});toast('Provider profile verification queued.');event.currentTarget.reset();syncProviderInfrastructureFields();await loadProviders();}catch(error){toast(error.message,'error');}
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
  if(button.dataset.providerProfileAction==='inspect'){showDetails(profile.displayName,`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(profile.id)}</dd><dt>State</dt><dd>${badge(profile.state)}</dd><dt>ClusterClass</dt><dd class="technical">${esc(profile.clusterClassName)}</dd><dt>Worker class</dt><dd class="technical">${esc(profile.workerClassName)}</dd><dt>Architectures</dt><dd class="technical">${esc((profile.architectures||[]).join(', '))}</dd><dt>Distribution identities</dt><dd class="technical">${esc((profile.distributionIdentities||profile.distributionProfiles||[]).join(', '))}</dd><dt>Provisioning mode</dt><dd>${esc(profile.provisioningMode||'cluster-api')}</dd><dt>Infrastructure provider</dt><dd>${esc(profile.infrastructureProvider||'unspecified')}</dd><dt>Infrastructure endpoint</dt><dd class="technical">${esc(profile.infrastructureEndpoint||'—')}</dd><dt>Credential reference</dt><dd class="technical">${esc(profile.credentialRef||'—')}</dd><dt>Observed digest</dt><dd class="technical">${esc(profile.observedDigest||'—')}</dd><dt>Last error</dt><dd>${esc(profile.lastError||'—')}</dd></dl>`);return;}
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
    const [deployments,verifications,closures,certifications,projects,clusterRows,catalogReleases,runtimeCertificationAuthority]=await Promise.all([softApi('/api/v1/baseline-deployments',[],'baseline deployments'),softApi('/api/v1/runtime-verifications',[],'runtime verifications'),softApi('/api/v1/runtime-closure-campaigns',[],'closure campaigns'),softApi('/api/v1/runtime-certifications',[],'runtime certifications'),softApi('/api/v1/projects',[],'projects'),softApi('/api/v1/clusters',[],'clusters'),softApi('/api/v1/catalog-releases',[],'catalog releases'),softApi('/api/v1/catalog/runtime-certification-authority',{components:[]},'component runtime certification authority')]);
    Object.assign(state,{baselineDeployments:deployments,verifications,closures,runtimeCertifications:certifications,projects,clusters:clusterRows,catalogReleases,runtimeCertificationAuthority});
    const successful=deployments.filter(d=>d.state==='SUCCEEDED'&&d.desiredDigest===d.observedDigest);
    setOptions($('#verification-baseline'),successful,item=>item.id,item=>`${item.baselineId}@${item.baselineVersion||''} · ${item.clusterId}`,'No successful baseline deployment');
    const closureCandidates=deployments.filter(d=>!['ROLLBACK_QUEUED','ROLLING_BACK','ROLLED_BACK'].includes(d.state));
    setOptions($('#closure-baseline'),closureCandidates,item=>item.id,item=>`${item.baselineId}@${item.baselineVersion||''} · ${item.state}`,'No eligible baseline deployment');
    prerequisite($('#verification-prerequisite'),deployments.length>0,'A baseline deployment is required before verification or closure. Certification additionally requires a fresh connected cluster and a published RENDER-or-higher Catalog release.','clusters','Connect a cluster');
    setIntrinsicDisabled($('#verification-form').querySelector('button[type="submit"]'), !successful.length);
    setIntrinsicDisabled($('#closure-form').querySelector('button[type="submit"]'), !closureCandidates.length);

    setProjectOptions($('#runtime-certification-project'),projects);
    const certificationProject=$('#runtime-certification-project').value;
    const clusters=clusterRows.map(row=>row.cluster||row).filter(cluster=>cluster.projectId===certificationProject&&cluster.inventoryDigest);
    setOptions($('#runtime-certification-cluster'),clusters,item=>item.id,item=>`${item.displayName} · ${item.kubernetesVersion||'version pending'} · ${shortDigest(item.inventoryDigest)}`,'Fresh cluster inventory required');
    const renderable=catalogReleases.filter(release=>release.state==='PUBLISHED'&&['RENDER','RUNTIME','PRODUCTION'].includes(release.channel));
    setOptions($('#runtime-certification-catalog'),renderable,item=>item.id,item=>`${item.catalogName}@${item.catalogVersion} · ${item.channel} · ${shortDigest(item.manifestDigest)}`,'Publish a RENDER-or-higher Catalog release first');
    const componentContracts=(runtimeCertificationAuthority?.components||[]).filter(item=>item?.sourceBinding?.resolved===true&&item?.executor?.profile==='COMPONENT_RUNTIME_V1'&&String(item?.executor?.status||'').startsWith('component-')&&item?.executor?.status!=='pending-component-executor');
    setOptions($('#runtime-certification-component'),componentContracts,item=>item.component,item=>`${item.component}@${item.release} · 5/6 lifecycle stages`,'No component executor is currently admitted');
    updateRuntimeCertificationProfileForm();

    $('#runtime-certification-grid').innerHTML=certifications.length?latest(certifications).map(run=>{
      const passed=(run.checks||[]).filter(check=>check.status==='PASS').length;
      const blocked=(run.checks||[]).filter(check=>check.status==='BLOCKED').length;
      return `<article class="resource-card"><div class="resource-header"><div><h3>${esc(run.profile)}</h3><div class="resource-meta">${badge(run.state)}${badge(run.phase)}${badge(`${passed}/${(run.checks||[]).length} PASS`)}${blocked?badge(`${blocked} BLOCKED`):''}</div></div></div><p>${technical(run.namespace)} · ${technical(run.clusterId)}</p><div class="resource-details">${detailRow('Catalog',run.catalogReleaseId,true)}${run.componentName?detailRow('Component',`${run.componentName}@${run.componentRelease}`,true):''}${detailRow('Inventory digest',shortDigest(run.inventoryDigest))}${detailRow('Source lock',shortDigest(run.sourceLockDigest))}${detailRow('Rendered',shortDigest(run.renderedDigest))}${detailRow('Resources',run.resourceCount||0)}${detailRow('Install checkpoint',shortDigest(run.installCheckpointDigest))}${detailRow('Evidence',shortDigest(run.evidenceDigest))}${detailRow('Expires',formatDate(run.expiresAt))}${detailRow('Attempt',run.taskAttempt||0)}</div>${run.lastError?`<div class="warning-banner">${esc(run.lastError)}</div>`:''}<details><summary>Certification checks (${(run.checks||[]).length})</summary><div class="activity-list">${(run.checks||[]).map(check=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">${check.status==='PASS'?'✓':check.status==='BLOCKED'?'⏸':'!'}</span><div><strong>${esc(check.key)}</strong><small>${esc(check.detail||'No detail')}</small></div></div>${badge(check.status)}</div>`).join('')||'<p>No checks reported yet.</p>'}</div></details><div class="resource-actions">${run.state==='SUCCEEDED'?`<a class="secondary small-button" href="/api/v1/runtime-certifications/${esc(run.id)}/report">View report</a><button type="button" class="danger small-button" data-certification-action="revoke" data-id="${esc(run.id)}">Revoke evidence</button>`:''}<button type="button" class="secondary small-button" data-certification-action="inspect" data-id="${esc(run.id)}">Inspect</button></div></article>`;
    }).join(''):emptyState('No runtime certification runs','Select a fresh connected cluster and a published RENDER-or-higher Catalog release.');

    $('#runtime-verification-grid').innerHTML=verifications.length?latest(verifications).map(v=>{
      const passed=(v.checks||[]).filter(c=>c.status==='PASS').length;
      return `<article class="resource-card"><div class="resource-header"><div><h3>${esc(v.state)}</h3><div class="resource-meta">${badge(v.state)}${badge(`${passed}/${(v.checks||[]).length} PASS`)}</div></div></div><p>Baseline ${technical(v.baselineDeploymentId)}</p><div class="resource-details">${detailRow('Probe image',v.probeImage||'—',true)}${detailRow('Desired',shortDigest(v.desiredDigest))}${detailRow('Observed',shortDigest(v.observedDigest))}${detailRow('Report',shortDigest(v.reportDigest))}</div>${v.lastError?`<div class="warning-banner">${esc(v.lastError)}</div>`:''}<details><summary>Runtime checks (${(v.checks||[]).length})</summary><div class="activity-list">${(v.checks||[]).map(check=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">${check.status==='PASS'?'✓':'!'}</span><div><strong>${esc(check.key)}</strong><small>${esc(check.detail||'No detail')}</small></div></div>${badge(check.status)}</div>`).join('')||'<p>No checks reported yet.</p>'}</div></details><div class="resource-actions">${v.state==='FAILED'?`<button type="button" class="primary small-button" data-verification-action="retry" data-id="${esc(v.id)}">Retry verification</button>`:''}${v.state==='SUCCEEDED'?`<a class="secondary small-button" href="/api/v1/runtime-verifications/${esc(v.id)}/report">Download report</a>`:''}<button type="button" class="secondary small-button" data-verification-action="inspect" data-id="${esc(v.id)}">Inspect</button></div></article>`;
    }).join(''):emptyState('No runtime verification','Apply a baseline successfully, then run the digest-pinned probe.');
    $('#runtime-closure-grid').innerHTML=closures.length?latest(closures).map(c=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(c.state)}</h3><div class="resource-meta">${badge(c.state)}${c.nextAction?badge(c.nextAction):''}</div></div></div><p>${esc(c.summary||'Awaiting controller action')}</p><div class="resource-details">${detailRow('Baseline',c.baselineDeploymentId,true)}${detailRow('Verification',c.runtimeVerificationId||'—',true)}${detailRow('Desired',shortDigest(c.desiredDigest))}${detailRow('Observed',shortDigest(c.observedDigest))}${detailRow('Evidence',shortDigest(c.evidenceDigest))}</div>${c.lastError?`<div class="warning-banner">${esc(c.lastError)}</div>`:''}<div class="resource-actions">${c.state!=='SUCCEEDED'&&c.state!=='FAILED'?`<button type="button" class="primary small-button" data-closure-action="advance" data-id="${esc(c.id)}">Advance one step</button>`:''}${c.state==='FAILED'?`<button type="button" class="primary small-button" data-closure-action="retry" data-id="${esc(c.id)}">Retry failed step</button>`:''}${c.state==='SUCCEEDED'?`<button type="button" class="primary small-button" data-closure-action="verify" data-viewer-safe="true" data-id="${esc(c.id)}">Verify evidence</button><a class="secondary small-button" href="/api/v1/runtime-closure-campaigns/${esc(c.id)}/report">Download closure report</a>`:''}<button type="button" class="secondary small-button" data-closure-action="inspect" data-id="${esc(c.id)}">Inspect</button></div></article>`).join(''):emptyState('No closure campaigns','Select a baseline deployment and create the first resumable campaign.');
  }catch(error){$('#runtime-verification-grid').innerHTML=errorState(error.message);$('#runtime-closure-grid').innerHTML=errorState(error.message);$('#runtime-certification-grid').innerHTML=errorState(error.message);}
}
function updateRuntimeCertificationProfileForm(){const profile=$('#runtime-certification-profile')?.value||'FOUNDATION_V1',componentMode=profile==='COMPONENT_RUNTIME_V1',field=$('#runtime-certification-component-field'),component=$('#runtime-certification-component'),button=$('#runtime-certification-form')?.querySelector('button[type="submit"]');if(field)field.hidden=!componentMode;if(component)component.required=componentMode;const namespace=$('#runtime-certification-namespace');if(namespace)namespace.value=profile==='TARGET_RUNTIME_V1'?'4so-cert-target-runtime':profile==='OBSERVABILITY_V1'?'4so-cert-observability':componentMode?'4so-component-cert':'4so-cert-foundation';if(button){const hasBase=Boolean($('#runtime-certification-project')?.value&&$('#runtime-certification-cluster')?.value&&$('#runtime-certification-catalog')?.value);setIntrinsicDisabled(button,!hasBase||(componentMode&&!component?.value));}}
$('#runtime-certification-project').onchange=()=>loadVerification();
$('#runtime-certification-cluster').onchange=()=>updateRuntimeCertificationProfileForm();
$('#runtime-certification-catalog').onchange=()=>updateRuntimeCertificationProfileForm();
$('#runtime-certification-component').onchange=()=>updateRuntimeCertificationProfileForm();
$('#runtime-certification-profile').onchange=()=>updateRuntimeCertificationProfileForm();
$('#runtime-certification-form').onsubmit=async event=>{event.preventDefault();updateRuntimeCertificationProfileForm();if(!event.currentTarget.reportValidity())return;const profile=$('#runtime-certification-profile').value;const body={projectId:$('#runtime-certification-project').value,clusterId:$('#runtime-certification-cluster').value,catalogReleaseId:$('#runtime-certification-catalog').value,profile,namespace:$('#runtime-certification-namespace').value.trim()};if(profile==='COMPONENT_RUNTIME_V1')body.componentName=$('#runtime-certification-component').value;try{const result=await api('/api/v1/runtime-certifications',{method:'POST',headers:{'Idempotency-Key':idempotency('runtime-certification')},body});toast(result.run?.state==='BLOCKED'?'Certification created as BLOCKED; inspect missing real capabilities.':'Runtime certification queued for the connected agent.',result.run?.state==='BLOCKED'?'warning':'success');await loadVerification();}catch(error){toast(error.message,'error');}};
$('#runtime-certification-grid').onclick=async event=>{const button=event.target.closest('[data-certification-action]');if(!button)return;const run=state.runtimeCertifications.find(item=>item.id===button.dataset.id);if(!run)return;const action=button.dataset.certificationAction;if(action==='inspect'){showDetails('Runtime certification',`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(run.id)}</dd><dt>Profile</dt><dd>${badge(run.profile)}</dd><dt>State</dt><dd>${badge(run.state)}</dd><dt>Phase</dt><dd>${badge(run.phase)}</dd><dt>Project</dt><dd class="technical">${esc(run.projectId)}</dd><dt>Cluster</dt><dd class="technical">${esc(run.clusterId)}</dd><dt>Catalog release</dt><dd class="technical">${esc(run.catalogReleaseId)}</dd><dt>Namespace</dt><dd class="technical">${esc(run.namespace)}</dd><dt>Inventory digest</dt><dd class="technical">${esc(run.inventoryDigest||'—')}</dd><dt>Environment fingerprint</dt><dd class="technical">${esc(run.environmentFingerprint||'—')}</dd><dt>Manifest digest</dt><dd class="technical">${esc(run.manifestDigest||'—')}</dd><dt>Source-lock digest</dt><dd class="technical">${esc(run.sourceLockDigest||'—')}</dd><dt>Rendered digest</dt><dd class="technical">${esc(run.renderedDigest||'—')}</dd><dt>Checkpoint</dt><dd class="technical">${esc(run.installCheckpointDigest||'—')}</dd><dt>Evidence</dt><dd class="technical">${esc(run.evidenceDigest||'—')}</dd><dt>Expires</dt><dd>${esc(formatDate(run.expiresAt))}</dd><dt>Error / blocker</dt><dd>${esc(run.lastError||'—')}</dd></dl><div class="warning-banner">External Live Certified: false · Production Ready: false. This record proves only the selected profile on the bound inventory/context.</div>`);return;}if(action==='revoke'){if(!await confirmAction('Revoke certification evidence',`Revoke ${run.profile} evidence for ${run.namespace}?`,true))return;try{await api(`/api/v1/runtime-certifications/${run.id}/revoke`,{method:'POST',headers:{'If-Match':`"${run.revision}"`},body:{}});toast('Certification evidence revoked.');await loadVerification();}catch(error){toast(error.message,'error');}}};
$('#verification-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const deployment=state.baselineDeployments.find(item=>item.id===$('#verification-baseline').value);try{await api('/api/v1/runtime-verifications',{method:'POST',headers:{'Idempotency-Key':idempotency('runtime-verification')},body:{projectId:deployment.projectId,clusterId:deployment.clusterId,baselineDeploymentId:deployment.id}});toast('Runtime verification queued for the connected agent.');await loadVerification();}catch(error){toast(error.message,'error');}};
$('#closure-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const deployment=state.baselineDeployments.find(item=>item.id===$('#closure-baseline').value);try{await api('/api/v1/runtime-closure-campaigns',{method:'POST',headers:{'Idempotency-Key':idempotency('runtime-closure')},body:{projectId:deployment.projectId,clusterId:deployment.clusterId,baselineDeploymentId:deployment.id}});toast('Runtime closure campaign created.');await loadVerification();}catch(error){toast(error.message,'error');}};
$('#runtime-verification-grid').onclick=async event=>{const button=event.target.closest('[data-verification-action]');if(!button)return;const record=state.verifications.find(item=>item.id===button.dataset.id);if(!record)return;if(button.dataset.verificationAction==='inspect'){showDetails('Runtime verification',`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(record.id)}</dd><dt>State</dt><dd>${badge(record.state)}</dd><dt>Baseline</dt><dd class="technical">${esc(record.baselineDeploymentId)}</dd><dt>Probe image</dt><dd class="technical">${esc(record.probeImage||'—')}</dd><dt>Desired digest</dt><dd class="technical">${esc(record.desiredDigest||'—')}</dd><dt>Observed digest</dt><dd class="technical">${esc(record.observedDigest||'—')}</dd><dt>Report digest</dt><dd class="technical">${esc(record.reportDigest||'—')}</dd><dt>Error</dt><dd>${esc(record.lastError||'—')}</dd></dl>`);return;}try{await api(`/api/v1/runtime-verifications/${record.id}/retry`,{method:'POST',headers:{'If-Match':`"${record.revision}"`},body:{}});toast('Runtime verification re-queued with the same identity and desired digest.');await loadVerification();}catch(error){toast(error.message,'error');}};
$('#runtime-closure-grid').onclick=async event=>{const button=event.target.closest('[data-closure-action]');if(!button)return;const record=state.closures.find(item=>item.id===button.dataset.id);if(!record)return;const action=button.dataset.closureAction;if(action==='inspect'){showDetails('Runtime closure campaign',`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(record.id)}</dd><dt>State</dt><dd>${badge(record.state)}</dd><dt>Next action</dt><dd>${esc(record.nextAction||'—')}</dd><dt>Summary</dt><dd>${esc(record.summary||'—')}</dd><dt>Baseline</dt><dd class="technical">${esc(record.baselineDeploymentId)}</dd><dt>Verification</dt><dd class="technical">${esc(record.runtimeVerificationId||'—')}</dd><dt>Evidence digest</dt><dd class="technical">${esc(record.evidenceDigest||'—')}</dd><dt>Error</dt><dd>${esc(record.lastError||'—')}</dd></dl>`);return;}try{if(action==='verify'){const report=await api(`/api/v1/runtime-closure-campaigns/${record.id}/report`);const result=await api('/api/v1/runtime-closure-reports/verify',{method:'POST',body:report});showDetails(t('verification.verifiedTitle','Verified closure evidence'),`<div class="success-banner">${esc(t('verification.verifiedMessage','Independent digest verification passed.'))}</div><dl class="key-value"><dt>Campaign</dt><dd class="technical">${esc(result.campaignId)}</dd><dt>Project</dt><dd class="technical">${esc(result.projectId)}</dd><dt>Cluster</dt><dd class="technical">${esc(result.clusterId)}</dd><dt>Baseline</dt><dd class="technical">${esc(result.baselineDeploymentId)}</dd><dt>Verification</dt><dd class="technical">${esc(result.runtimeVerificationId)}</dd><dt>Evidence digest</dt><dd class="technical">${esc(result.evidenceDigest)}</dd><dt>Canonicalization</dt><dd class="technical">${esc(result.canonicalization)}</dd></dl><div class="warning-banner">${esc(t('verification.integrityOnly','This verifies evidence integrity only; Runtime Certified, HA Certified and Production Ready remain false.'))}</div>`);return;}await api(`/api/v1/runtime-closure-campaigns/${record.id}/${action}`,{method:'POST',headers:{'If-Match':`"${record.revision}"`},body:{}});toast(`Closure campaign ${action} accepted.`);await loadVerification();}catch(error){toast(error.message,'error');}};

async function loadWorkspaces(){
  try{
    const [projects,clusterRows,workspaces]=await Promise.all([
      softApi('/api/v1/projects',[],'projects'),
      softApi('/api/v1/clusters',[],'clusters'),
      softApi('/api/v1/workspaces',[],'workspaces')
    ]);
    const clusters=clusterRows.map(row=>row.cluster||row);
    Object.assign(state,{projects,clusters,workspaces});
    const projectById=new Map(projects.map(item=>[item.id,item]));
    const clusterById=new Map(clusters.map(item=>[item.id,item]));
    prerequisite($('#workspaces-prerequisite'),projects.length>0,'Create a project before creating a Workspace.','workspace','Open organizations & projects');
    setProjectOptions($('#workspace-authority-project'),projects);

    const previousWorkspace=$('#workspace-binding-workspace').value||$('#virtual-cluster-workspace').value;
    setOptions($('#workspace-binding-workspace'),workspaces,item=>item.id,item=>`${item.displayName} · ${projectById.get(item.projectId)?.displayName||item.projectId}`,'Create a Workspace first');
    setOptions($('#virtual-cluster-workspace'),workspaces,item=>item.id,item=>`${item.displayName} · ${projectById.get(item.projectId)?.displayName||item.projectId}`,'Create a Workspace first');
    if(previousWorkspace && workspaces.some(item=>item.id===previousWorkspace)){
      $('#workspace-binding-workspace').value=previousWorkspace;
      $('#virtual-cluster-workspace').value=previousWorkspace;
    }
    const selectedWorkspace=workspaces.find(item=>item.id===$('#workspace-binding-workspace').value) || workspaces[0] || null;
    if(selectedWorkspace){
      $('#workspace-binding-workspace').value=selectedWorkspace.id;
      $('#virtual-cluster-workspace').value=selectedWorkspace.id;
    }

    const eligibleClusters=selectedWorkspace?clusters.filter(item=>item.projectId===selectedWorkspace.projectId):[];
    setOptions($('#workspace-binding-cluster'),eligibleClusters,item=>item.id,item=>`${item.displayName||item.name||item.id} · ${item.kubernetesVersion||'version pending'}`,'No managed cluster in this project');
    const [bindings,virtualClusters]=selectedWorkspace?await Promise.all([
      softApi(`/api/v1/workspaces/${encodeURIComponent(selectedWorkspace.id)}/bindings`,[],'workspace bindings'),
      softApi(`/api/v1/workspaces/${encodeURIComponent(selectedWorkspace.id)}/virtual-clusters`,[],'virtual clusters')
    ]):[[],[]];
    state.workspaceBindings=bindings;
    state.virtualClusters=virtualClusters;
    const activeBindings=bindings.filter(item=>item.state==='ACTIVE');
    setOptions($('#virtual-cluster-binding'),activeBindings,item=>item.id,item=>`${clusterById.get(item.clusterId)?.displayName||clusterById.get(item.clusterId)?.name||item.clusterId} · ${item.namespace}`,'No active namespace binding');

    $('#workspace-authority-grid').innerHTML=workspaces.length?workspaces.map(item=>{
      const selected=selectedWorkspace?.id===item.id;
      return `<article class="resource-card${selected?' selected':''}"><div class="resource-header"><div><h3>${esc(item.displayName||item.name)}</h3><div class="resource-meta">${badge('REFERENCE_ONLY')}${selected?badge('SELECTED'):''}</div></div></div><p>${esc(item.description||'Project-scoped cross-cluster namespace boundary')}</p><div class="resource-details">${detailRow('Project',projectById.get(item.projectId)?.displayName||item.projectId)}${detailRow('Machine name',item.name,true)}${detailRow('Authority','WORKSPACE_AUTHORITY_V1',true)}${detailRow('Digest',shortDigest(item.digest))}${detailRow('Revision',item.revision)}</div><div class="resource-actions"><button class="secondary small-button" type="button" data-workspace-select="${esc(item.id)}">View namespace bindings</button></div></article>`;
    }).join(''):emptyState('No Workspaces','Create a reference-only project boundary before binding namespaces.');

    $('#workspace-binding-grid').innerHTML=bindings.length?bindings.map(item=>{
      const cluster=clusterById.get(item.clusterId);
      return `<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.namespace)}</h3><div class="resource-meta">${badge(item.state)}</div></div></div><p>${esc(cluster?.displayName||cluster?.name||item.clusterId)}</p><div class="resource-details">${detailRow('Cluster',item.clusterId,true)}${detailRow('Namespace',item.namespace,true)}${detailRow('Runtime state','Derived from referenced cluster')}${detailRow('Revision',item.revision)}</div><div class="resource-actions">${item.state==='ACTIVE'?`<button class="danger small-button" type="button" data-workspace-binding-action="revoke" data-id="${esc(item.id)}">Revoke binding</button>`:''}<button class="secondary small-button" type="button" data-workspace-binding-action="inspect" data-id="${esc(item.id)}">Inspect reference</button></div></article>`;
    }).join(''):emptyState(selectedWorkspace?'No namespace bindings':'No Workspace selected',selectedWorkspace?'Bind an existing managed-cluster namespace. Runtime data stays on the cluster.':'Create a Workspace first.');

    $('#virtual-cluster-grid').innerHTML=virtualClusters.length?virtualClusters.map(item=>{
      const runtimePending=['REQUESTED','PROVISIONING','SUSPENDING','RESUMING','DELETING'].includes(item.state);
      const runtimeTruth=item.state==='RECOVERY_REQUIRED'
        ?'Runtime outcome is ambiguous; automatic replay is blocked until authoritative recovery.'
        :runtimePending
          ?'Lifecycle work is queued or reconciling; this is not a terminal Ready result.'
          :item.state==='DELETED'
            ?'Runtime workload deletion is authoritatively observed; Physical certification remains separate.'
            :'Lifecycle state is authoritative; Exact-SHA Physical certification remains independent.';
      const actions=[`<button class="secondary small-button" type="button" data-virtual-cluster-action="inspect" data-id="${esc(item.id)}">Inspect runtime journal</button>`];
      if(item.state==='ACTIVE')actions.unshift(`<button class="secondary small-button" type="button" data-virtual-cluster-action="suspend" data-id="${esc(item.id)}">Suspend</button>`);
      if(item.state==='SUSPENDED')actions.unshift(`<button class="primary small-button" type="button" data-virtual-cluster-action="resume" data-id="${esc(item.id)}">Resume</button>`);
      if(['REQUESTED','ACTIVE','SUSPENDED','FAILED'].includes(item.state))actions.push(`<button class="danger small-button" type="button" data-virtual-cluster-action="delete" data-id="${esc(item.id)}">Delete runtime</button>`);
      actions.push(`<button class="quiet small-button" type="button" data-virtual-cluster-finops="${esc(item.id)}">FinOps scope</button>`);
      return `<article class="resource-card" data-project-scope="${esc(item.projectId)}" data-scope-access="write"><div class="resource-header"><div><h3>${esc(item.name)}</h3><div class="resource-meta">${badge(item.state)}${item.developerMode?badge('DEVELOPER'):badge('TEAM')}</div></div></div><p>${esc(runtimeTruth)}</p><div class="resource-details">${detailRow('Profile',item.profile)}${detailRow('Host cluster',item.hostClusterId,true)}${detailRow('Host namespace',item.hostNamespace,true)}${detailRow('Kubernetes',item.kubernetesVersion,true)}${detailRow('CPU',String(item.cpuMilli)+'m')}${detailRow('Memory',String(item.memoryMiB)+' MiB')}${detailRow('Storage',String(item.storageGiB)+' GiB')}${detailRow('Max namespaces',item.maxNamespaces)}${detailRow('Phase',item.phase||'—')}${detailRow('Pending action',item.pendingAction||'—')}${detailRow('Task action',item.taskAction||'—')}${detailRow('Task fence',item.taskFenceToken||'—')}${detailRow('Desired digest',shortDigest(item.desiredDigest))}${detailRow('Observed digest',item.observedDigest?shortDigest(item.observedDigest):'Not converged')}${detailRow('FinOps attribution',`${item.projectId} · ${item.hostClusterId} · ${item.hostNamespace}`,true)}${detailRow('Revision',item.revision)}</div><div class="resource-actions">${actions.join('')}</div></article>`;
    }).join(''):emptyState(selectedWorkspace?'No virtual cluster requests':'No Workspace selected',selectedWorkspace?'Create a bounded desired-state request from an active namespace binding.':'Create a Workspace first.');

    $('#workspace-authority-project').onchange=()=>queueMicrotask(()=>applyAccessMode());
    $('#workspace-binding-workspace').onchange=async()=>{const id=$('#workspace-binding-workspace').value;$('#virtual-cluster-workspace').value=id;await loadWorkspaces();};
    $('#virtual-cluster-workspace').onchange=async()=>{const id=$('#virtual-cluster-workspace').value;$('#workspace-binding-workspace').value=id;await loadWorkspaces();};
    $('#virtual-cluster-profile').onchange=()=>{const developer=$('#virtual-cluster-profile').value==='developer';$('#virtual-cluster-cpu').max=developer?'4000':'16000';$('#virtual-cluster-memory').max=developer?'8192':'32768';$('#virtual-cluster-storage').max=developer?'100':'500';$('#virtual-cluster-namespaces').max=developer?'5':'20';if(developer && Number($('#virtual-cluster-sleep').value)<15)$('#virtual-cluster-sleep').value='60';};

    $('#workspace-authority-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;try{await api('/api/v1/workspaces',{method:'POST',body:{projectId:$('#workspace-authority-project').value,name:$('#workspace-authority-name').value.trim(),displayName:$('#workspace-authority-display').value.trim(),description:$('#workspace-authority-description').value.trim()}});toast('Workspace authority created.');event.currentTarget.reset();await loadWorkspaces();}catch(error){toast(error.message,'error');}};
    $('#workspace-binding-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const workspaceId=$('#workspace-binding-workspace').value;if(!workspaceId){toast('Create or select a Workspace first.','error');return;}try{await api(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/bindings`,{method:'POST',body:{clusterId:$('#workspace-binding-cluster').value,namespace:$('#workspace-binding-namespace').value.trim()}});toast('Namespace reference bound to Workspace.');$('#workspace-binding-namespace').value='';await loadWorkspaces();}catch(error){toast(error.message,'error');}};
    $('#virtual-cluster-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const workspaceId=$('#virtual-cluster-workspace').value;if(!workspaceId){toast('Create or select a Workspace first.','error');return;}try{
      const response=await api(`/api/v1/workspaces/${encodeURIComponent(workspaceId)}/virtual-clusters`,{method:'POST',headers:{'Idempotency-Key':idempotency('virtual-cluster-create')},body:{
        workspaceBindingId:$('#virtual-cluster-binding').value,
        name:$('#virtual-cluster-name').value.trim(),
        profile:$('#virtual-cluster-profile').value,
        kubernetesVersion:$('#virtual-cluster-version').value.trim(),
        cpuMilli:Number($('#virtual-cluster-cpu').value),
        memoryMiB:Number($('#virtual-cluster-memory').value),
        storageGiB:Number($('#virtual-cluster-storage').value),
        maxNamespaces:Number($('#virtual-cluster-namespaces').value),
        sleepAfterMinutes:Number($('#virtual-cluster-sleep').value)
      }});
      toast(response.idempotentReplay?'Virtual cluster request already exists with the same idempotency key.':'Virtual cluster desired state recorded and queued. REQUESTED is not Running or Ready.');
      $('#virtual-cluster-name').value='';
      await loadWorkspaces();
    }catch(error){toast(error.message,'error');}};

    $('#workspace-authority-grid').onclick=async event=>{const button=event.target.closest('[data-workspace-select]');if(!button)return;$('#workspace-binding-workspace').value=button.dataset.workspaceSelect;$('#virtual-cluster-workspace').value=button.dataset.workspaceSelect;await loadWorkspaces();};
    $('#workspace-binding-grid').onclick=async event=>{const button=event.target.closest('[data-workspace-binding-action]');if(!button)return;const binding=state.workspaceBindings.find(item=>item.id===button.dataset.id);if(!binding)return;const workspace=state.workspaces.find(item=>item.id===binding.workspaceId);if(button.dataset.workspaceBindingAction==='inspect'){showDetails('Workspace namespace reference',`<div class="inline-summary"><strong>Reference-only authority.</strong> Workload, quota, health, observability and cost state are not persisted in the Workspace record.</div><dl class="key-value"><dt>Workspace</dt><dd>${esc(workspace?.displayName||binding.workspaceId)}</dd><dt>Project</dt><dd class="technical">${esc(binding.projectId)}</dd><dt>Cluster</dt><dd class="technical">${esc(binding.clusterId)}</dd><dt>Namespace</dt><dd class="technical">${esc(binding.namespace)}</dd><dt>State</dt><dd>${badge(binding.state)}</dd><dt>Revision</dt><dd>${esc(binding.revision)}</dd></dl>`);return;}if(button.dataset.workspaceBindingAction==='revoke'){if(!await confirmAction('Revoke Workspace binding',`Remove ${binding.namespace} from ${workspace?.displayName||'this Workspace'}? This changes only the product reference; it does not delete the namespace or workloads.`,true))return;try{await api(`/api/v1/workspaces/${encodeURIComponent(binding.workspaceId)}/bindings/${encodeURIComponent(binding.id)}/revoke`,{method:'POST',headers:{'If-Match':`"${binding.revision}"`},body:{}});toast('Workspace binding revoked. The namespace and workloads were not deleted.');await loadWorkspaces();}catch(error){toast(error.message,'error');}}};
    $('#virtual-cluster-grid').onclick=async event=>{
      const finopsButton=event.target.closest('[data-virtual-cluster-finops]');
      if(finopsButton){
        const item=state.virtualClusters.find(row=>row.id===finopsButton.dataset.virtualClusterFinops);
        if(item){
          toast(`Opening FinOps for project-scoped measured usage. Attribution key: ${item.projectId} / ${item.hostClusterId} / ${item.hostNamespace}`);
          await navigate('finops');
        }
        return;
      }
      const button=event.target.closest('[data-virtual-cluster-action]');
      if(!button)return;
      const item=state.virtualClusters.find(row=>row.id===button.dataset.id);
      if(!item)return;
      const action=button.dataset.virtualClusterAction;
      if(action==='inspect'){
        showDetails('Virtual cluster runtime journal',`<div class="warning-banner">Lifecycle state is durable and executor-backed. Exact-SHA Physical certification remains independent and is never inferred here.</div><dl class="key-value"><dt>ID</dt><dd class="technical">${esc(item.id)}</dd><dt>State</dt><dd>${badge(item.state)}</dd><dt>Phase</dt><dd>${esc(item.phase||'—')}</dd><dt>Pending action</dt><dd>${esc(item.pendingAction||'—')}</dd><dt>Task action</dt><dd>${esc(item.taskAction||'—')}</dd><dt>Task attempt</dt><dd>${esc(item.taskAttempt||0)}</dd><dt>Task fence token</dt><dd>${esc(item.taskFenceToken||0)}</dd><dt>Dispatch acknowledged</dt><dd>${esc(item.taskDispatchedAt||'No active dispatched mutation')}</dd><dt>Workspace</dt><dd class="technical">${esc(item.workspaceId)}</dd><dt>Binding revision</dt><dd>${esc(item.workspaceBindingRevision)}</dd><dt>Host cluster</dt><dd class="technical">${esc(item.hostClusterId)}</dd><dt>Host namespace</dt><dd class="technical">${esc(item.hostNamespace)}</dd><dt>Runtime source digest</dt><dd class="technical">${esc(item.runtimeSourceDigest||'Not claimed')}</dd><dt>Desired digest</dt><dd class="technical">${esc(item.desiredDigest)}</dd><dt>Observed digest</dt><dd class="technical">${esc(item.observedDigest||'Not converged')}</dd><dt>FinOps attribution</dt><dd class="technical">${esc(item.projectId)} / ${esc(item.hostClusterId)} / ${esc(item.hostNamespace)}</dd><dt>Last error</dt><dd>${esc(item.lastError||'—')}</dd></dl><div class="inline-summary"><strong>Evidence boundary:</strong> desired/observed digest, WorkspaceBinding revision, task fence and dispatch journal are product authority. Physical certification is tracked separately.</div>`);
        return;
      }
      const labels={suspend:'Suspend virtual cluster',resume:'Resume virtual cluster',delete:'Delete virtual cluster runtime'};
      const impacts={suspend:'Scale the exact owned vCluster StatefulSet to zero and persist pause metadata. This does not delete the Workspace binding.',resume:'Restore replicas only from the product-owned pause journal and require authoritative readback before ACTIVE.',delete:'Uninstall the exact vCluster runtime and require authoritative workload absence before DELETED. The Workspace record remains auditable.'};
      if(!await confirmAction(labels[action]||'Virtual cluster lifecycle',impacts[action]||'Apply the requested lifecycle action?',action==='delete'))return;
      const headers={'If-Match':`"${item.revision}"`,'Idempotency-Key':`virtual-cluster-${action}-${item.id}-r${item.revision}`};
      if(action==='delete')headers['X-Confirm-Delete']='delete-virtual-cluster';
      try{
        const response=await api(`/api/v1/workspaces/${encodeURIComponent(item.workspaceId)}/virtual-clusters/${encodeURIComponent(item.id)}/${encodeURIComponent(action)}`,{method:'POST',headers,body:{}});
        toast(response.idempotentReplay?`${labels[action]} request already recorded; refreshed authoritative state.`:`${labels[action]} requested. Completion requires runtime readback.`);
        await loadWorkspaces();
      }catch(error){toast(error.message,'error');}
    };
    applyAccessMode($('#workspaces'));
  }catch(error){
    if(error?.name==='AbortError')throw error;
    $('#workspace-authority-grid').innerHTML=errorState('Workspace authority unavailable',error.message);
    $('#workspace-binding-grid').innerHTML='';
    $('#virtual-cluster-grid').innerHTML='';
  }
}

const finOpsEndpoints={budgetPolicies:'/api/v1/finops/budget-policies',insights:'/api/v1/finops/insights',rateCards:'/api/v1/finops/rate-cards',usage:'/api/v1/finops/usage-measurements',capacity:'/api/v1/finops/capacity-observations',showback:'/api/v1/finops/showback',chargeback:'/api/v1/finops/chargeback-export'};
function finOpsMoney(micros,currency){
  if(micros===null||micros===undefined)return 'Cost unavailable';
  const raw=typeof micros==='string'?micros:String(micros);
  if(!/^-?\d+$/.test(raw))return 'Cost unavailable';
  try{
    const value=BigInt(raw),negative=value<0n,abs=negative?-value:value,whole=abs/1000000n,fraction=(abs%1000000n).toString().padStart(6,'0').replace(/0+$/,'');
    return `${negative?'-':''}${whole.toString()}${fraction?'.'+fraction:''} ${currency||''}`.trim();
  }catch(_error){return 'Cost unavailable';}
}
function finOpsMicrosInput(id){
  const raw=$(id).value.trim();
  if(!/^\d+$/.test(raw))throw new Error('Rate-card prices must be non-negative integer micro-currency values.');
  const value=BigInt(raw);
  if(value>9223372036854775807n)throw new Error('Rate-card price exceeds the supported int64 micro-currency range.');
  if(value>9007199254740991n)throw new Error('Rate-card price exceeds the browser exact-integer range. Use API automation for larger values.');
  return Number(value);
}
function finOpsBudgetMicrosInput(id){
  const raw=$(id).value.trim();
  if(!/^\d+$/.test(raw)||raw==='0')throw new Error('Budget limit must be a positive integer micro-currency value.');
  const value=BigInt(raw);
  if(value>9007199254740991n)throw new Error('Budget limit exceeds the browser exact-integer range. Use API automation for larger values.');
  return Number(value);
}
function finOpsPercentBasisPoints(id){
  const raw=$(id).value.trim();
  if(!/^\d+(?:\.\d{1,2})?$/.test(raw))throw new Error('Budget thresholds must be percentages with at most two decimal places.');
  const [whole,fraction='']=raw.split('.');
  return Number(BigInt(whole)*100n+BigInt((fraction+'00').slice(0,2)));
}
function finOpsInsightWindow(usage){
  const loaded=finOpsWindow(usage);
  const observed=loaded?new Date(loaded.to):new Date();
  const start=loaded?new Date(loaded.from):new Date(Date.UTC(observed.getUTCFullYear(),observed.getUTCMonth(),1));
  let forecastEnd=new Date(Date.UTC(observed.getUTCFullYear(),observed.getUTCMonth()+1,1));
  if(forecastEnd<observed)forecastEnd=new Date(observed);
  return {windowStart:start.toISOString(),observedThrough:observed.toISOString(),forecastEnd:forecastEnd.toISOString()};
}
function finOpsUsageComplete(item){
  const metrics=item?.metrics||{};
  return ['CPU_CORE_HOUR','MEMORY_GIB_HOUR','STORAGE_GIB_HOUR','ACCELERATOR_HOUR'].every(metric=>metrics[metric]?.available===true);
}
function finOpsMetricSummary(item){
  const metrics=item?.metrics||{};
  return Object.entries(metrics).map(([name,sample])=>`${name}: ${sample?.available?String(sample.quantityMicros)+' µunits':'missing'}`).join(' · ');
}
function finOpsWindow(usage){
  const valid=usage.filter(item=>item?.windowStart&&item?.windowEnd);
  if(!valid.length)return null;
  const from=new Date(Math.min(...valid.map(item=>new Date(item.windowStart).getTime())));
  const to=new Date(Math.max(...valid.map(item=>new Date(item.windowEnd).getTime())));
  if(!Number.isFinite(from.getTime())||!Number.isFinite(to.getTime())||to<=from)return null;
  return {from:from.toISOString(),to:to.toISOString()};
}
async function loadFinOps(){
  try{
    const [organizations,projects]=await Promise.all([softApi('/api/v1/organizations',[],'organizations'),softApi('/api/v1/projects',[],'projects')]);
    Object.assign(state,{organizations,projects});
    const scopedProject=projects.find(item=>item.id===state.globalScope.projectId)||null;
    const organizationId=scopedProject?.organizationId||state.globalScope.organizationId||organizations[0]?.id||'';
    prerequisite($('#finops-prerequisite'),Boolean(organizationId),'Select or create an organization before reviewing FinOps.','workspace','Open organizations & projects');
    setOptions($('#finops-rate-card-organization'),organizations,item=>item.id,item=>`${item.displayName||item.name} · ${item.id}`,'Create an organization first');
    setOptions($('#finops-budget-organization'),organizations,item=>item.id,item=>`${item.displayName||item.name} · ${item.id}`,'Create an organization first');
    const budgetProjects=projects.filter(item=>item.organizationId===organizationId);
    setOptions($('#finops-budget-project'),budgetProjects,item=>item.id,item=>`${item.displayName||item.name} · ${item.id}`,'Organization total');
    if(organizationId&&organizations.some(item=>item.id===organizationId)){ $('#finops-rate-card-organization').value=organizationId; $('#finops-budget-organization').value=organizationId; }
    if(scopedProject&&budgetProjects.some(item=>item.id===scopedProject.id))$('#finops-budget-project').value=scopedProject.id;
    if(!$('#finops-rate-card-effective').value)$('#finops-rate-card-effective').value=localDateTimeValue(new Date());
    if(!$('#finops-budget-effective').value)$('#finops-budget-effective').value=localDateTimeValue(new Date());
    if(!organizationId){state.finOpsBudgetPolicies=[];state.finOpsInsights=null;state.finOpsRateCards=[];state.finOpsUsage=[];state.finOpsCostSummary=null;state.finOpsChargeback=null;$('#finops-cost-summary').innerHTML='';$('#finops-insight-summary').innerHTML='';$('#finops-budget-grid').innerHTML=emptyState('No organization scope','Choose an organization to review budget policies.');$('#finops-rightsizing-grid').innerHTML='';$('#finops-rate-card-grid').innerHTML=emptyState('No organization scope','Choose an organization to review rate cards.');$('#finops-usage-grid').innerHTML='';$('#finops-chargeback-grid').innerHTML='';return;}
    const projectId=scopedProject?.organizationId===organizationId?scopedProject.id:'';
    const scopeQuery=projectId?`projectId=${encodeURIComponent(projectId)}`:`organizationId=${encodeURIComponent(organizationId)}`;
    const [budgetPolicies,rateCards,usage,capacity]=await Promise.all([
      softApi(`${finOpsEndpoints.budgetPolicies}?${scopeQuery}`,[],'FinOps budget policies'),
      softApi(`${finOpsEndpoints.rateCards}?organizationId=${encodeURIComponent(organizationId)}`,[],'FinOps rate cards'),
      softApi(`${finOpsEndpoints.usage}?${scopeQuery}&limit=500`,[],'FinOps usage'),
      softApi(`${finOpsEndpoints.capacity}?${scopeQuery}&limit=100`,[],'FinOps capacity')
    ]);
    const sortedCards=[...rateCards].sort((a,b)=>new Date(b.effectiveFrom)-new Date(a.effectiveFrom)||String(b.version).localeCompare(String(a.version)));
    const card=sortedCards[0]||null;
    const window=finOpsWindow(usage);
    let showback=null;
    if(card&&window){
      const query=`${scopeQuery}&currency=${encodeURIComponent(card.currency)}&groupBy=PROJECT&from=${encodeURIComponent(window.from)}&to=${encodeURIComponent(window.to)}`;
      showback=await softApi(`${finOpsEndpoints.showback}?${query}`,null,'FinOps showback');
      const exportLink=$('#finops-chargeback-export');
      if(exportLink){exportLink.href=`${finOpsEndpoints.chargeback}?${query}`;exportLink.hidden=false;}
    }else{
      const exportLink=$('#finops-chargeback-export');
      if(exportLink){exportLink.removeAttribute('href');exportLink.hidden=true;}
    }
    const insightWindow=finOpsInsightWindow(usage);
    const insightCurrency=card?.currency||budgetPolicies[0]?.currency||'USD';
    const insightQuery=`${scopeQuery}&currency=${encodeURIComponent(insightCurrency)}&windowStart=${encodeURIComponent(insightWindow.windowStart)}&observedThrough=${encodeURIComponent(insightWindow.observedThrough)}&forecastEnd=${encodeURIComponent(insightWindow.forecastEnd)}`;
    const insights=await softApi(`${finOpsEndpoints.insights}?${insightQuery}`,null,'FinOps insights');
    Object.assign(state,{finOpsBudgetPolicies:budgetPolicies,finOpsInsights:insights,finOpsRateCards:sortedCards,finOpsUsage:usage,finOpsCapacity:capacity,finOpsCostSummary:showback,finOpsChargeback:showback});
    const missingMeasurements=usage.filter(item=>!finOpsUsageComplete(item)).length;
    const status=showback?.complete?'AVAILABLE':card&&window?'INCOMPLETE':card?'NO USAGE':'NO RATE CARD';
    $('#finops-cost-summary').innerHTML=`<article class="metric-card"><span>Cost status</span><strong>${esc(status)}</strong><small>${missingMeasurements?`${esc(missingMeasurements)} measurement(s) contain missing telemetry`:'No hidden telemetry gap in loaded usage'}</small></article><article class="metric-card"><span>Authoritative total</span><strong>${esc(showback?.complete?finOpsMoney(showback.totalCostMicros,showback.currency):'Cost unavailable')}</strong><small>${showback?`Known subtotal ${esc(finOpsMoney(showback.knownCostMicros,showback.currency))}`:'Measured usage plus a covering rate card is required'}</small></article><article class="metric-card"><span>Usage / capacity</span><strong>${esc(usage.length)} / ${esc(capacity.length)}</strong><small>Trusted collector records only</small></article><article class="metric-card"><span>Rate card</span><strong>${esc(card?`${card.name}@${card.version}`:'Not configured')}</strong><small>${esc(card?.currency||'No pricing authority')}</small></article>`;
    const forecastReady=insights?.forecast?.status==='READY'&&insights.forecast.projectedCostMicros!==null&&insights.forecast.projectedCostMicros!==undefined;
    const evaluatedBudgets=insights?.budgets||[];
    const budgetSeverity=evaluatedBudgets.length?(evaluatedBudgets.find(item=>item.severity==='CRITICAL')?.severity||evaluatedBudgets.find(item=>item.severity==='WARNING')?.severity||evaluatedBudgets[0].severity):'NOT CONFIGURED';
    $('#finops-insight-summary').innerHTML=`<article class="metric-card"><span>Forecast</span><strong>${esc(forecastReady?finOpsMoney(insights.forecast.projectedCostMicros,insights.currency):'Forecast unavailable')}</strong><small>${esc(forecastReady?`${insights.forecast.confidence} confidence · deterministic linear projection`:insights?.forecast?.reason||'Measured cost evidence is required')}</small></article><article class="metric-card"><span>Budget state</span><strong>${esc(budgetSeverity)}</strong><small>${esc(evaluatedBudgets.length?`${evaluatedBudgets.length} policy evaluation(s)`:'No matching immutable budget policy')}</small></article><article class="metric-card"><span>Spend-rate anomaly</span><strong>${esc(insights?.anomaly?.status==='READY'?insights.anomaly.severity:'Unknown')}</strong><small>${esc(insights?.anomaly?.status==='READY'?`${insights.anomaly.ratioBasisPoints} bp recent/baseline`:insights?.anomaly?.reason||'Insufficient measured history')}</small></article><article class="metric-card"><span>Rightsizing</span><strong>${esc((insights?.rightsizing||[]).filter(item=>item.status==='READY').length)} evidence-backed</strong><small>Review only · never auto-applied</small></article>`;
    $('#finops-budget-grid').innerHTML=budgetPolicies.length?budgetPolicies.map(item=>{const evaluation=evaluatedBudgets.find(row=>row.policyId===item.id);return `<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.name)}@${esc(item.version)}</h3><div class="resource-meta">${badge(item.currency)}${badge(evaluation?.severity||'NOT EVALUATED')}</div></div></div><p>${esc(finOpsMoney(item.limitMicros,item.currency))} budget limit</p><div class="resource-details">${detailRow('Scope',item.projectId||'Organization total',true)}${detailRow('Warning',`${item.warningBasisPoints/100}%`)}${detailRow('Critical',`${item.criticalBasisPoints/100}%`)}${detailRow('Projected',evaluation?.projectedCostMicros!==null&&evaluation?.projectedCostMicros!==undefined?finOpsMoney(evaluation.projectedCostMicros,item.currency):'Forecast unavailable')}${detailRow('Digest',shortDigest(item.digest))}</div></article>`;}).join(''):emptyState('No budget policies','Publish an immutable budget guardrail. Forecasts stay unavailable until measured cost evidence is complete.');
    const rightsizing=insights?.rightsizing||[];
    $('#finops-rightsizing-grid').innerHTML=rightsizing.length?rightsizing.map(item=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.metric)}</h3><div class="resource-meta">${badge(item.status)}${badge(item.action)}</div></div></div><p>${esc(item.status==='READY'?`${(Number(item.utilizationBasisPoints||0)/100).toFixed(2)}% average utilization`:'Recommendation unavailable')}</p><div class="resource-details">${detailRow('Average demand',item.averageDemandMicros||'—',true)}${detailRow('Capacity',item.capacityMicros||'—',true)}${detailRow('Evidence',item.evidenceObservationId||'—',true)}${detailRow('Automation','Review only · never auto-applied')}</div></article>`).join(''):emptyState('No rightsizing evidence','A fresh project-aggregate capacity observation plus complete measured usage is required.');
    $('#finops-rate-card-grid').innerHTML=sortedCards.length?sortedCards.map(item=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.name)}@${esc(item.version)}</h3><div class="resource-meta">${badge(item.currency)}${item.id===card?.id?badge('LATEST'):''}</div></div></div><p>Effective ${formatDate(item.effectiveFrom)}${item.effectiveUntil?` → ${formatDate(item.effectiveUntil)}`:' · open ended'}</p><div class="resource-details">${Object.entries(item.rates||{}).sort(([a],[b])=>a.localeCompare(b)).map(([metric,price])=>detailRow(metric,`${esc(price)} micros / unit`,true)).join('')}${detailRow('Digest',shortDigest(item.digest))}</div></article>`).join(''):emptyState('No rate cards','Publish an immutable organization rate card to derive cost from measured usage.');
    $('#finops-usage-grid').innerHTML=usage.length?latest(usage,12).map(item=>{const complete=finOpsUsageComplete(item);return `<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.namespace||item.workspaceId||item.clusterId||item.projectId)}</h3><div class="resource-meta">${badge(complete?'MEASURED':'INCOMPLETE')}${!complete?badge('COST UNAVAILABLE'):''}</div></div></div><p>${esc(finOpsMetricSummary(item)||'No metric data')}</p><div class="resource-details">${detailRow('Project',item.projectId,true)}${detailRow('Cluster',item.clusterId||'—',true)}${detailRow('Window',`${formatDate(item.windowStart)} → ${formatDate(item.windowEnd)}`)}${detailRow('Source',item.source,true)}${detailRow('Digest',shortDigest(item.digest))}</div></article>`;}).join(''):emptyState('No usage observations','Trusted collectors have not reported measured usage yet. Missing telemetry is not treated as zero.');
    const groups=showback?.groups||[];
    $('#finops-chargeback-grid').innerHTML=groups.length?groups.map(group=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(group.key)}</h3><div class="resource-meta">${badge(group.complete?'COMPLETE':'INCOMPLETE')}${group.attributionComplete?badge('ATTRIBUTED'):badge('UNATTRIBUTED')}</div></div></div><p>${esc(group.complete?finOpsMoney(group.totalCostMicros,showback.currency):'Cost unavailable')}</p><div class="resource-details">${detailRow('Known subtotal',finOpsMoney(group.knownCostMicros,showback.currency))}${detailRow('Measurements',group.measurementCount)}${detailRow('Missing telemetry',(group.missingTelemetry||[]).join(', ')||'None')}${detailRow('Missing rates',(group.missingRates||[]).join(', ')||'None')}</div></article>`).join(''):emptyState(card?(window?'No chargeback groups':'No usage window'):'No rate card selected',card?'No complete measured usage falls inside the current scope.':'Publish a rate card before deriving chargeback.');
    $('#finops-rate-card-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;try{const organizationID=$('#finops-rate-card-organization').value;const body={organizationId:organizationID,name:$('#finops-rate-card-name').value.trim(),version:$('#finops-rate-card-version').value.trim(),currency:$('#finops-rate-card-currency').value.trim().toUpperCase(),effectiveFrom:new Date($('#finops-rate-card-effective').value).toISOString(),rates:{CPU_CORE_HOUR:finOpsMicrosInput('#finops-price-cpu'),MEMORY_GIB_HOUR:finOpsMicrosInput('#finops-price-memory'),STORAGE_GIB_HOUR:finOpsMicrosInput('#finops-price-storage'),ACCELERATOR_HOUR:finOpsMicrosInput('#finops-price-accelerator')}};await api(finOpsEndpoints.rateCards,{method:'POST',headers:{'Idempotency-Key':idempotency('finops-rate-card')},body});toast('Immutable FinOps rate card published.');await loadFinOps();}catch(error){toast(error.message,'error');}};
    $('#finops-budget-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;try{const warning=finOpsPercentBasisPoints('#finops-budget-warning'),critical=finOpsPercentBasisPoints('#finops-budget-critical');if(critical<=warning)throw new Error('Critical budget threshold must be greater than warning threshold.');const body={organizationId:$('#finops-budget-organization').value,projectId:$('#finops-budget-project').value||'',name:$('#finops-budget-name').value.trim(),version:$('#finops-budget-version').value.trim(),currency:$('#finops-budget-currency').value.trim().toUpperCase(),effectiveFrom:new Date($('#finops-budget-effective').value).toISOString(),limitMicros:finOpsBudgetMicrosInput('#finops-budget-limit'),warningBasisPoints:warning,criticalBasisPoints:critical};await api(finOpsEndpoints.budgetPolicies,{method:'POST',headers:{'Idempotency-Key':idempotency('finops-budget-policy')},body});toast('Immutable FinOps budget policy published.');await loadFinOps();}catch(error){toast(error.message,'error');}};
    applyAccessMode($('#finops'));
  }catch(error){if(error?.name==='AbortError')throw error;$('#finops-cost-summary').innerHTML='';$('#finops-insight-summary').innerHTML='';$('#finops-budget-grid').innerHTML=errorState('FinOps unavailable',error.message);$('#finops-rightsizing-grid').innerHTML='';$('#finops-rate-card-grid').innerHTML=errorState('FinOps unavailable',error.message);$('#finops-usage-grid').innerHTML='';$('#finops-chargeback-grid').innerHTML='';}
}

async function loadReliability(projectId, projectClusters){
  const emptyHealth={authority:'SERVICE_HEALTH_AUTHORITY_V1',coverageStatus:'UNKNOWN',summary:{UNKNOWN:0},clusters:[]};
  const emptyDelivery={authority:'DELIVERY_INSIGHTS_AUTHORITY_V1',deploymentFrequency:{status:'UNKNOWN',unit:'deployments-per-day-micros',sampleSize:0},leadTimeForChanges:{status:'UNKNOWN',unit:'seconds',sampleSize:0},changeFailureRate:{status:'UNKNOWN',unit:'basis-points',sampleSize:0},failedDeploymentRecovery:{status:'UNKNOWN',unit:'seconds',sampleSize:0},missingEvidence:['deployment-events','source-commit-timestamps','matched-incident-open-resolve-pairs'],physicalCertificationInferred:false};
  const deliveryTo=new Date(),deliveryFrom=new Date(deliveryTo.getTime()-30*24*60*60*1000);
  const deliveryQuery=projectId?`projectId=${encodeURIComponent(projectId)}&from=${encodeURIComponent(deliveryFrom.toISOString())}&to=${encodeURIComponent(deliveryTo.toISOString())}`:'';
  const [serviceHealth,incidents,sloPolicies,reliabilityErrorBudgets,deliveryInsights]=projectId?await Promise.all([
    softApi(`/api/v1/reliability/service-health?projectId=${encodeURIComponent(projectId)}`,emptyHealth,'reliability service health'),
    softApi(`/api/v1/reliability/incidents?projectId=${encodeURIComponent(projectId)}&limit=100`,[],'reliability incidents'),
    softApi(`/api/v1/reliability/slo-policies?projectId=${encodeURIComponent(projectId)}&limit=100`,[],'reliability SLO policies'),
    softApi(`/api/v1/reliability/error-budgets?projectId=${encodeURIComponent(projectId)}`,[],'reliability error budgets'),
    softApi(`/api/v1/reliability/delivery-insights?${deliveryQuery}`,emptyDelivery,'delivery insights')
  ]):[emptyHealth,[],[],[],emptyDelivery];
  Object.assign(state,{reliabilityServiceHealth:serviceHealth,reliabilityIncidents:incidents,reliabilitySLOPolicies:sloPolicies,reliabilityErrorBudgets,reliabilityDeliveryInsights:deliveryInsights});
  const deliveryValue=(metric,kind)=>{
    if(!metric||metric.status!=='OBSERVED')return 'UNKNOWN';
    const value=Number(metric.value||0);
    if(kind==='frequency')return `${(value/1000000).toFixed(2)}/day`;
    if(kind==='rate')return `${(value/100).toFixed(2)}%`;
    return `${value}s`;
  };
  $('#reliability-delivery-summary').innerHTML=[
    ['Deployment frequency',deliveryValue(deliveryInsights?.deploymentFrequency,'frequency'),deliveryInsights?.deploymentFrequency],
    ['Lead time for changes',deliveryValue(deliveryInsights?.leadTimeForChanges,'seconds'),deliveryInsights?.leadTimeForChanges],
    ['Change failure rate',deliveryValue(deliveryInsights?.changeFailureRate,'rate'),deliveryInsights?.changeFailureRate],
    ['Incident recovery',deliveryValue(deliveryInsights?.failedDeploymentRecovery,'seconds'),deliveryInsights?.failedDeploymentRecovery]
  ].map(([label,value,metric])=>`<article class="metric-card"><strong>${esc(value)}</strong><span>${esc(label)}</span><small>${esc(metric?.status==='OBSERVED'?`${metric.sampleSize||0} evidence sample(s)`:'Insufficient source evidence')}</small></article>`).join('');
  const missing=deliveryInsights?.missingEvidence||[];
  $('#reliability-delivery-evidence').innerHTML=`<strong>Window</strong> ${esc(deliveryFrom.toLocaleDateString())} → ${esc(deliveryTo.toLocaleDateString())} · <strong>Evidence</strong> ${esc(deliveryInsights?.evidenceCount||0)} · <strong>Missing</strong> ${esc(missing.length?missing.join(', '):'none')} · Physical certification is never inferred from these analytics.`;
  const reliabilityCoverageStatus=String(serviceHealth?.coverageStatus||'UNKNOWN').toUpperCase();
  const openIncidents=(incidents||[]).filter(item=>item.state!=='RESOLVED').length;
  const completeBudgets=(reliabilityErrorBudgets||[]).filter(item=>item.projection?.coverageStatus==='COMPLETE').length;
  $('#reliability-summary').innerHTML=[['Coverage',reliabilityCoverageStatus,`${serviceHealth?.returnedClusters||0}/${serviceHealth?.clusterCount||0} clusters`],['Open incidents',openIncidents,`${(incidents||[]).length} loaded`],['SLO policies',(sloPolicies||[]).length,`${completeBudgets} budget(s) complete`]].map(([label,value,detail])=>`<article class="metric-card"><strong>${esc(value)}</strong><span>${esc(label)}</span><small>${esc(detail)}</small></article>`).join('');
  const healthById=new Map((serviceHealth?.clusters||[]).map(item=>[item.clusterId,item]));
  $('#reliability-cluster-grid').innerHTML=projectClusters.length?projectClusters.map(cluster=>{const row=healthById.get(cluster.id)||{health:'UNKNOWN',coverageStatus:'UNKNOWN',reason:'No reliability observation'};return `<article class="resource-card"><div class="resource-header"><div><h3>${esc(cluster.displayName||cluster.name||cluster.id)}</h3><div class="resource-meta">${badge(row.health||'UNKNOWN')}${badge(row.coverageStatus||'UNKNOWN')}</div></div></div><div class="resource-details">${detailRow('Cluster',cluster.id,true)}${detailRow('Observed',row.observedAt?formatDate(row.observedAt):'—')}${detailRow('Reason',row.reason||'—')}</div></article>`;}).join(''):emptyState('No reliability targets','Select a project with connected clusters.');
  setOptions($('#reliability-incident-cluster'),projectClusters,item=>item.id,item=>item.displayName||item.name||item.id,'Project-wide');
  $('#reliability-incident-cluster').insertAdjacentHTML('afterbegin','<option value="">Project-wide</option>');
  setOptions($('#reliability-slo-cluster'),projectClusters,item=>item.id,item=>item.displayName||item.name||item.id,'Connect a cluster first');
  const budgetByPolicy=new Map((reliabilityErrorBudgets||[]).map(item=>[item.policy?.id,item]));
  $('#reliability-incident-grid').innerHTML=(incidents||[]).length?latest(incidents).map(item=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.service||'Project incident')}</h3><div class="resource-meta">${badge(item.state)}${badge(item.severity||'UNKNOWN')}</div></div></div><div class="resource-details">${detailRow('Cluster',item.clusterId||'Project-wide',true)}${detailRow('Revision',item.revision)}${detailRow('Updated',formatDate(item.updatedAt))}${item.resolutionSummary?detailRow('Resolution',item.resolutionSummary):''}</div><div class="resource-actions">${item.state==='OPEN'?`<button class="secondary small-button" type="button" data-reliability-incident-action="acknowledge" data-id="${esc(item.id)}">Acknowledge</button>`:''}${item.state!=='RESOLVED'?`<button class="primary small-button" type="button" data-reliability-incident-action="resolve" data-id="${esc(item.id)}">Resolve</button>`:''}</div></article>`).join(''):emptyState('No incidents','No reliability incident is recorded for this project.');
  $('#reliability-slo-grid').innerHTML=(sloPolicies||[]).length?latest(sloPolicies).map(policy=>{const budget=budgetByPolicy.get(policy.id);return `<article class="resource-card"><div class="resource-header"><div><h3>${esc(policy.name)}</h3><div class="resource-meta">${badge(budget?.projection?.coverageStatus||'UNKNOWN')}</div></div></div><div class="resource-details">${detailRow('Cluster',policy.clusterId,true)}${detailRow('Objective',`${(Number(policy.objectiveBasisPoints||0)/100).toFixed(2)}%`)}${detailRow('Window',`${policy.windowSeconds}s`)}${detailRow('Observation interval',`${policy.observationIntervalSeconds}s`)}${detailRow('Revision',policy.revision)}</div><div class="resource-actions"><button class="secondary small-button" type="button" data-reliability-slo-action="revise" data-id="${esc(policy.id)}">Revise</button></div></article>`;}).join(''):emptyState('No SLO policies','Create the first cluster-targeted SLO policy.');
  $('#reliability-error-budget-grid').innerHTML=(reliabilityErrorBudgets||[]).length?reliabilityErrorBudgets.map(view=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(view.policy?.name||'SLO')}</h3><div class="resource-meta">${badge(view.projection?.coverageStatus||'UNKNOWN')}</div></div></div><div class="resource-details">${detailRow('Observed',`${view.projection?.observedObservations||0}/${view.projection?.expectedObservations||0}`)}${detailRow('Bad observations',view.projection?.badObservations||0)}${detailRow('Remaining budget',view.projection?.remainingBudgetBasisPoints==null?'UNKNOWN':`${view.projection.remainingBudgetBasisPoints} bp`)}${detailRow('Burn ratio',view.projection?.burnRatioMilli==null?'UNKNOWN':`${view.projection.burnRatioMilli/1000}x`)}${detailRow('Reason',view.reason||'—')}</div></article>`).join(''):emptyState('No error budgets','Error budgets appear after an SLO policy exists.');
}

async function loadFleet(){
  try{
    const [projects,clusters,groups,drifts,campaigns,baselines,recoveryCheckpoints,day2CampaignEngine]=await Promise.all([softApi('/api/v1/projects',[],'projects'),softApi('/api/v1/clusters',[],'clusters'),softApi('/api/v1/fleet-groups',[],'fleet groups'),softApi('/api/v1/drift-scans',[],'drift scans'),softApi('/api/v1/upgrade-campaigns',[],'upgrade campaigns'),softApi('/api/v1/baselines',[],'baselines'),softApi('/api/v1/recovery-checkpoints',[],'recovery checkpoints'),softApi('/api/v1/day2-campaign-engine',{},'Day-2 campaign engine')]);
    Object.assign(state,{projects,clusters,fleetGroups:groups,driftScans:drifts,upgradeCampaigns:campaigns,baselines,recoveryCheckpoints,day2CampaignEngine:day2CampaignEngine?.authority?day2CampaignEngine:state.day2CampaignEngine});
    setProjectOptions($('#fleet-project'),projects);
    setProjectOptions($('#operations-search-project'),projects);
    if($('#fleet-project').value&&[...$('#operations-search-project').options].some(option=>option.value===$('#fleet-project').value))$('#operations-search-project').value=$('#fleet-project').value;
    const projectId=$('#fleet-project').value;
    const [backupPolicies,dataProtectionRuns]=projectId?await Promise.all([softApi(`/api/v1/backup-policies?projectId=${encodeURIComponent(projectId)}`,[],'backup policies'),softApi(`/api/v1/data-protection-runs?projectId=${encodeURIComponent(projectId)}`,[],'data protection runs')]):[[],[]];
    Object.assign(state,{backupPolicies,dataProtectionRuns});
    const fleetHealth=projectId?await api(`/api/v1/fleet/health?projectId=${encodeURIComponent(projectId)}`):{summary:{total:0,healthy:0,warning:0,stale:0,critical:0,online:0,eol:0},clusters:[]}; state.fleetHealth=fleetHealth;
    const projectClusters=clusters.map(row=>row.cluster||row).filter(cluster=>!projectId||cluster.projectId===projectId);
    await loadReliability(projectId,projectClusters);
    setOptions($('#fleet-clusters'),projectClusters,item=>item.id,item=>`${item.displayName} · ${item.kubernetesVersion||'version pending'}`,'Connect clusters first');
    setOptions($('#recovery-cluster'),projectClusters.filter(item=>item.inventoryDigest),item=>item.id,item=>`${item.displayName} · ${shortDigest(item.inventoryDigest)}`,'Fresh cluster inventory required');
    setOptions($('#data-protection-cluster'),projectClusters.filter(item=>item.inventoryDigest),item=>item.id,item=>`${item.displayName} · ${shortDigest(item.inventoryDigest)}`,'Fresh cluster inventory required');
    const policyById=new Map(backupPolicies.map(item=>[item.id,item]));
    $('#data-protection-policy-grid').innerHTML=backupPolicies.length?latest(backupPolicies).map(item=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.name)}</h3><div class="resource-meta">${badge(item.state)}${badge(item.provider)}</div></div></div><p>${esc(item.includedNamespaces?.join(', ')||'No namespaces')}</p><div class="resource-details">${detailRow('Cluster',item.clusterId,true)}${detailRow('UTC schedule',item.schedule,true)}${detailRow('Retention',item.retention,true)}${detailRow('Storage location',item.backupStorageLocation,true)}${detailRow('Credential reference',item.credentialRef,true)}${detailRow('Desired digest',shortDigest(item.desiredDigest))}</div><div class="resource-actions">${item.state==='ACTIVE'?`<button class="primary small-button" type="button" data-dp-policy-action="backup" data-id="${esc(item.id)}">Run backup</button><button class="secondary small-button" type="button" data-dp-policy-action="disable" data-id="${esc(item.id)}">Disable schedule</button>`:`<button class="primary small-button" type="button" data-dp-policy-action="enable" data-id="${esc(item.id)}">Enable schedule</button>`}<button class="secondary small-button" type="button" data-dp-policy-action="inspect" data-id="${esc(item.id)}">Inspect</button></div></article>`).join(''):emptyState('No backup policies','Create a policy for a connected cluster with current inventory and Velero capability.');
    $('#data-protection-run-grid').innerHTML=dataProtectionRuns.length?latest(dataProtectionRuns).map(item=>{const policy=policyById.get(item.policyId);const successfulBackup=item.kind==='BACKUP'&&item.state==='SUCCEEDED';return `<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.kind)} · ${esc(policy?.name||item.policyId)}</h3><div class="resource-meta">${badge(item.state)}</div></div></div><div class="resource-details">${detailRow('Cluster',item.clusterId,true)}${detailRow('Reference',item.reference||'—',true)}${detailRow('Recovery checkpoint',item.recoveryCheckpointId||'—',true)}${detailRow('Evidence',shortDigest(item.evidenceDigest))}${detailRow('Requested by',item.requestedBy||'—')}${detailRow('Approved by',item.approvedBy||'—')}${detailRow('Error',item.lastError||'—')}</div><div class="resource-actions">${successfulBackup?`<button class="secondary small-button" type="button" data-dp-run-action="drill" data-id="${esc(item.id)}">Run restore drill</button><button class="danger small-button" type="button" data-dp-run-action="restore" data-id="${esc(item.id)}">Request restore</button>`:''}${item.kind==='RESTORE'&&item.state==='AWAITING_APPROVAL'?`<button class="primary small-button" type="button" data-dp-run-action="approve" data-id="${esc(item.id)}">Approve restore</button>`:''}<button class="secondary small-button" type="button" data-dp-run-action="inspect" data-id="${esc(item.id)}">Inspect</button></div></article>`}).join(''):emptyState('No backup or restore runs','Run a backup from an active policy. Successful backups can be used for restore drills or approval-gated restores.');
    if(!$('#recovery-completed-at').value) $('#recovery-completed-at').value=localDateTimeValue(new Date(Date.now()-5*60000));
    if(!$('#recovery-expires-at').value) $('#recovery-expires-at').value=localDateTimeValue(new Date(Date.now()+24*3600000));
    const visibleCheckpoints=recoveryCheckpoints.filter(item=>!projectId||item.projectId===projectId);
    $('#recovery-checkpoint-grid').innerHTML=visibleCheckpoints.length?latest(visibleCheckpoints).map(item=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.provider)} · ${esc(item.reference)}</h3><div class="resource-meta">${badge(item.state)}${new Date(item.expiresAt)>new Date()?badge('VALID'):badge('EXPIRED')}</div></div></div><div class="resource-details">${detailRow('Cluster',item.clusterId,true)}${detailRow('Evidence',shortDigest(item.evidenceDigest))}${detailRow('وضعیت ثبت‌شده',shortDigest(item.inventoryDigest))}${detailRow('Completed',formatDate(item.completedAt))}${detailRow('Expires',formatDate(item.expiresAt))}${detailRow('Revision',item.revision)}</div><div class="resource-actions">${item.state==='VERIFIED'?`<button type="button" class="danger small-button" data-recovery-action="revoke" data-id="${esc(item.id)}">Revoke checkpoint</button>`:''}<button type="button" class="secondary small-button" data-recovery-action="inspect" data-id="${esc(item.id)}">Inspect</button></div></article>`).join(''):emptyState('No recovery checkpoints','Register backup evidence captured against current cluster inventory before creating an upgrade campaign.');
    const visibleGroups=groups.filter(group=>!projectId||group.projectId===projectId);
    prerequisite($('#fleet-prerequisite'),projectClusters.length>0,'At least one connected cluster is required before creating a fleet.','clusters','Connect clusters');
    setIntrinsicDisabled($('#fleet-group-form').querySelector('button[type="submit"]'), !projectClusters.length);
    const hs=fleetHealth.summary||{};
    $('#fleet-health-summary').innerHTML=[['Clusters',hs.total||0,`${hs.online||0} online`],['Healthy',hs.healthy||0,'fresh and supported'],['Warning',hs.warning||0,`${hs.eol||0} EOL`],['Stale / critical',(hs.stale||0)+(hs.critical||0),'requires operator attention']].map(([label,value,detail])=>`<article class="metric-card"><strong>${esc(value)}</strong><span>${esc(label)}</span><small>${esc(detail)}</small></article>`).join('');
    $('#fleet-health-grid').innerHTML=(fleetHealth.clusters||[]).length?(fleetHealth.clusters||[]).map(row=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(row.displayName||row.name)}</h3><div class="resource-meta">${badge(row.health)}${badge(row.online?'ONLINE':'OFFLINE')}${badge(row.kubernetesSupport?.status||'UNKNOWN')}</div></div></div><div class="resource-details">${detailRow('Kubernetes',row.kubernetesVersion||'—',true)}${detailRow('Support EOL',row.kubernetesSupport?.endOfLife?new Date(row.kubernetesSupport.endOfLife).toLocaleDateString():'unknown')}${detailRow('Nodes',`${row.readyNodes||0}/${row.nodeCount||0} Ready`)}${detailRow('Storage classes',row.storageClassCount||0)}${detailRow('Default storage',row.defaultStorageClass||'—',true)}${detailRow('CPU allocatable',`${row.capacity?.cpuAllocatableMilli||0}m`)}${detailRow('Memory allocatable',bytes(row.capacity?.memoryAllocatableBytes))}${detailRow('CNI',row.networking?.cni||'unknown',true)}${detailRow('Ingress',(row.networking?.ingressControllers||[]).join(', ')||'unknown',true)}</div>${(row.warnings||[]).length?`<div class="warning-banner">${(row.warnings||[]).map(esc).join('<br>')}</div>`:''}<div class="resource-actions"><button type="button" class="secondary small-button" data-health-action="timeline" data-id="${esc(row.clusterId)}">Timeline</button><button type="button" class="secondary small-button" data-health-action="bundle" data-id="${esc(row.clusterId)}">Support bundle</button></div></article>`).join(''):emptyState('No fleet health data','Connect a cluster and wait for the first inventory report.');
    $('#fleet-group-grid').innerHTML=visibleGroups.length?visibleGroups.map(group=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(group.displayName)}</h3><div class="resource-meta">${badge(`${group.clusterIds.length} clusters`)}</div></div></div><div class="resource-details">${detailRow('Machine name',group.name,true)}${detailRow('Project',group.projectId,true)}${detailRow('Revision',group.revision)}</div><details><summary>Cluster IDs</summary><pre class="code-block technical" dir="ltr">${esc(group.clusterIds.join('\n'))}</pre></details><div class="resource-actions"><button type="button" class="secondary small-button" data-fleet-action="drift" data-id="${esc(group.id)}">Run drift scan</button><button type="button" class="primary small-button" data-fleet-action="upgrade" data-id="${esc(group.id)}">Create upgrade campaign</button></div></article>`).join(''):emptyState('No fleet groups','Select connected clusters and create the first fleet group.');
    $('#drift-scan-grid').innerHTML=drifts.length?latest(drifts).map(scan=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(scan.state)}</h3><div class="resource-meta">${badge(scan.state)}${badge(`${(scan.targets||[]).length} targets`)}</div></div></div><p>${esc(scan.summary||'Agent checks are pending.')}</p><div class="activity-list">${(scan.targets||[]).map(target=>{const git=target.git;return `<div class="activity-item"><div class="activity-main"><span class="check-icon">${target.state==='IN_SYNC'?'✓':target.state==='FAILED'?'!':'○'}</span><div><strong class="technical">${esc(target.clusterId)}</strong><small>${esc(target.baselineVersion||'No baseline')} · ${(target.changes||[]).filter(change=>change.action!=='NOOP').length} baseline changes${git?` · Git ${esc(git.classification)}`:''}</small>${git?`<small>Base ${esc(shortDigest(git.baseDigest))} → Git ${esc(shortDigest(git.currentDigest))} → Live ${esc(shortDigest(git.observedDigest||'UNKNOWN'))}</small>${git.changedFiles?.length?`<small>${git.changedFiles.length} externally changed Git file(s)</small>`:''}`:''}${target.comparison?`<small>Product ${esc(shortDigest(target.comparison.productGeneratedDigest))}${target.comparison.gitDesiredDigest?` → Git ${esc(shortDigest(target.comparison.gitDesiredDigest))}`:''} → Live ${esc(shortDigest(target.comparison.liveObservedDigest||'UNKNOWN'))} · ${esc(target.comparison.classification)}</small>`:''}</div></div><div>${badge(target.state)}${git?badge(git.currentTrusted?'TRUSTED':'UNTRUSTED'):''}</div>${(target.findings||[]).length?`<div class="resource-details">${target.findings.map(finding=>`<div class="detail-row"><span>${badge(finding.severity)} ${badge(finding.category)} <strong>${esc(finding.code)}</strong></span><small>${esc(finding.summary)} · Owner ${esc(finding.owner)} · Seen ${esc(finding.occurrences||1)}×</small>${finding.remediation?.mode==='OPERATION'&&finding.remediation?.eligible?`<button type="button" class="secondary small-button" data-drift-action="remediate-finding" data-scan-id="${esc(scan.id)}" data-cluster-id="${esc(target.clusterId)}" data-fingerprint="${esc(finding.fingerprint)}">Queue ${esc(finding.remediation.action)}</button>`:`<small>Remediation: ${esc(finding.remediation?.action||'REVIEW')} · ${esc(finding.remediation?.mode||'GUIDANCE')}</small>`}</div>`).join('')}</div>`:''}${git?.adoptable?`<button type="button" class="secondary small-button" data-drift-action="adopt-git" data-scan-id="${esc(scan.id)}" data-cluster-id="${esc(target.clusterId)}">Adopt trusted Git state</button>`:''}</div>`}).join('')}</div></article>`).join(''):emptyState('No drift scans','Run a live read-only drift scan from a fleet group.');
    $('#upgrade-campaign-grid').innerHTML=campaigns.length?latest(campaigns).map(campaign=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(campaign.targetVersion)}</h3><div class="resource-meta">${badge(campaign.state)}${badge(`wave ${campaign.currentWave||0}`)}</div></div></div><p>${esc(campaign.summary||'Awaiting campaign action.')}</p><div class="resource-details">${detailRow('Authority',state.day2CampaignEngine?.authority||'GENERALIZED_DAY2_CAMPAIGN_ENGINE_V1',true)}${detailRow('Canary count',campaign.canaryCount)}${detailRow('Window start',formatDate(campaign.maintenanceWindowStart))}${detailRow('Window end',formatDate(campaign.maintenanceWindowEnd))}${detailRow('Plan valid until',formatDate(campaign.planExpiresAt))}${detailRow('Recovery checkpoints',(campaign.recoveryCheckpointIds||[]).length)}${detailRow('Revalidations',campaign.planRevalidationCount||0)}${detailRow('Revision',campaign.revision)}</div><details><summary>Targets (${(campaign.targets||[]).length})</summary><div class="activity-list">${(campaign.targets||[]).map(target=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">${target.wave}</span><div><strong class="technical">${esc(target.clusterId)}</strong><small>Wave ${target.wave}</small></div></div>${badge(target.state)}</div>`).join('')}</div></details><div class="resource-actions">${campaign.state==='AWAITING_APPROVAL'?approvalControl(campaign,'Approve campaign',`data-upgrade-action="approve" data-id="${esc(campaign.id)}"`):''}${['AWAITING_APPROVAL','QUEUED','RUNNING','PAUSED'].includes(campaign.state)?`<button type="button" class="secondary small-button" data-upgrade-action="revalidate" data-id="${esc(campaign.id)}">Revalidate / reschedule</button>`:''}${campaign.state==='RUNNING'?`<button type="button" class="secondary small-button" data-upgrade-action="pause" data-id="${esc(campaign.id)}">Pause safely</button>`:''}${campaign.state==='PAUSED'?`<button type="button" class="primary small-button" data-upgrade-action="resume" data-id="${esc(campaign.id)}">Resume campaign</button>`:''}${['QUEUED','RUNNING','HALTED','PAUSE_REQUESTED','CANCEL_REQUESTED'].includes(campaign.state)?`<button type="button" class="primary small-button" data-upgrade-action="advance" data-id="${esc(campaign.id)}">${['PAUSE_REQUESTED','CANCEL_REQUESTED'].includes(campaign.state)?'Drain active work':'Advance campaign'}</button>`:''}${!['SUCCEEDED','FAILED','CANCELLED','CANCEL_REQUESTED'].includes(campaign.state)?`<button type="button" class="danger small-button" data-upgrade-action="cancel" data-id="${esc(campaign.id)}">Cancel safely</button>`:''}<button type="button" class="secondary small-button" data-upgrade-action="inspect" data-id="${esc(campaign.id)}">Inspect</button></div></article>`).join(''):emptyState('No upgrade campaigns','Create an upgrade campaign from an eligible fleet group.');
  }catch(error){$('#fleet-health-grid').innerHTML=errorState(error.message);$('#recovery-checkpoint-grid').innerHTML=errorState(error.message);$('#fleet-group-grid').innerHTML=errorState(error.message);$('#drift-scan-grid').innerHTML=errorState(error.message);$('#upgrade-campaign-grid').innerHTML=errorState(error.message);}
}
async function downloadSupportBundle(body,statusSelector='#fleet-support-status'){
  const status=$(statusSelector)||$('#fleet-support-status');if(status)status.innerHTML='<div class="inline-summary">Support bundle job queued. Waiting for sealed evidence…</div>';
  const created=await api('/api/v1/support-bundle-jobs',{method:'POST',headers:{'Idempotency-Key':idempotency('support-bundle')},body});
  const operationId=created.operation?.id;if(!operationId)throw new Error('Support bundle job did not return an operation ID.');
  let job=created;
  for(let attempt=0;attempt<30;attempt++){
    job=await api(`/api/v1/support-bundle-jobs/${encodeURIComponent(operationId)}`);
    const opState=job.operation?.state||'';
    if(job.ready)break;
    if(['FAILED','CANCELLED','ROLLED_BACK','ROLLBACK_FAILED','NEEDS_OPERATOR'].includes(opState))throw new Error(job.operation?.lastError||`Support bundle job ended in ${opState}.`);
    if(status)status.innerHTML=`<div class="inline-summary">Support bundle ${esc(opState||'QUEUED')} · operation <span class="technical">${esc(operationId)}</span></div>`;
    await new Promise(resolve=>setTimeout(resolve,500));
  }
  if(!job.ready)throw new Error(`Support bundle is still running as operation ${operationId}. Follow it in Operations and retry download when evidence is sealed.`);
  const result=await apiBlob(`/api/v1/support-bundle-jobs/${encodeURIComponent(operationId)}/download`);
  const match=/filename="?([^";]+)"?/i.exec(result.disposition),name=match?.[1]||'4so-support-bundle.zip',url=URL.createObjectURL(result.blob),a=document.createElement('a');
  a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1500);
  if(status)status.innerHTML=`<div class="success-banner">Durable support bundle sealed and verified · operation <span class="technical">${esc(operationId)}</span> · digest <span class="technical">${esc(result.digest||job.evidence?.digest||'—')}</span></div>`;
}
$('#fleet-health-grid').onclick=async event=>{const button=event.target.closest('[data-health-action]');if(!button)return;try{if(button.dataset.healthAction==='timeline'){const events=await api(`/api/v1/clusters/${button.dataset.id}/timeline`);showDetails('Cluster timeline',events.length?`<div class="activity-list">${events.slice(0,100).map(item=>`<div class="activity-item"><div><strong>${esc(item.action)}</strong><small>${esc(item.resourceType)} · ${esc(item.resourceId)} · ${new Date(item.occurredAt).toLocaleString()}</small></div>${badge(item.actorId||'system')}</div>`).join('')}</div>`:emptyState('No timeline events','No related audit events are available yet.'));return;}await downloadSupportBundle({profile:'cluster-diagnostics',clusterId:button.dataset.id});toast('Cluster support bundle downloaded.');}catch(error){toast(error.message,'error');}};
$('#operations-search-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const projectId=$('#operations-search-project').value,query=$('#operations-search-query').value.trim();$('#operations-search-status').innerHTML='<div class="inline-summary">Searching bounded project projection…</div>';try{const result=await api(`/api/v1/search?projectId=${encodeURIComponent(projectId)}&q=${encodeURIComponent(query)}`);$('#operations-search-status').innerHTML=`<div class="success-banner"><strong>${esc(result.resultCount||0)} result(s)</strong> · backend <span class="technical">${esc(result.backend||'postgresql-bounded')}</span> · source of truth: no</div>`;$('#operations-search-results').innerHTML=(result.results||[]).length?(result.results||[]).map(item=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.title||item.id)}</h3><div class="resource-meta">${badge((item.type||'record').toUpperCase())}</div></div></div><p>${esc(item.summary||'No summary')}</p><div class="resource-details">${detailRow('Source',item.sourceRef||'—',true)}${detailRow('Updated',formatDate(item.updatedAt))}${detailRow('Digest',shortDigest(item.digest||''))}</div></article>`).join(''):emptyState('No search results','Try a cluster name, operation kind, evidence kind or audit actor/resource.');}catch(error){$('#operations-search-status').innerHTML=errorState(error.message);$('#operations-search-results').innerHTML='';}};
$('#fleet-support-download').onclick=async()=>{const projectId=$('#fleet-project').value;if(!projectId){toast('Select a project first.','error');return;}try{await downloadSupportBundle({profile:'fleet-diagnostics',projectId});toast('Project support bundle downloaded.');}catch(error){toast(error.message,'error');}};
$('#data-protection-policy-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const cluster=state.clusters.map(row=>row.cluster||row).find(item=>item.id===$('#data-protection-cluster').value);if(!cluster){toast('Select a connected cluster with current inventory.','error');return;}const includedNamespaces=$('#data-protection-namespaces').value.split(',').map(item=>item.trim()).filter(Boolean);try{await api('/api/v1/backup-policies',{method:'POST',body:{projectId:cluster.projectId,clusterId:cluster.id,name:$('#data-protection-name').value.trim(),provider:'velero',backupStorageLocation:$('#data-protection-storage-location').value.trim(),credentialRef:$('#data-protection-credential-ref').value.trim(),schedule:$('#data-protection-schedule').value.trim(),retention:$('#data-protection-retention').value.trim(),includedNamespaces}});toast('Backup policy created. Scheduled backups are now controlled by the policy state.');event.currentTarget.reset();await loadFleet();}catch(error){toast(error.message,'error');}};
$('#data-protection-policy-grid').onclick=async event=>{const button=event.target.closest('[data-dp-policy-action]');if(!button)return;const item=state.backupPolicies.find(row=>row.id===button.dataset.id);if(!item)return;const action=button.dataset.dpPolicyAction;if(action==='inspect'){showDetails('Backup policy',`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(item.id)}</dd><dt>State</dt><dd>${badge(item.state)}</dd><dt>Cluster</dt><dd class="technical">${esc(item.clusterId)}</dd><dt>Schedule</dt><dd class="technical">${esc(item.schedule)}</dd><dt>Retention</dt><dd class="technical">${esc(item.retention)}</dd><dt>Namespaces</dt><dd>${esc((item.includedNamespaces||[]).join(', '))}</dd><dt>Storage location</dt><dd class="technical">${esc(item.backupStorageLocation)}</dd><dt>Credential reference</dt><dd class="technical">${esc(item.credentialRef)}</dd><dt>Desired digest</dt><dd class="technical">${esc(item.desiredDigest)}</dd></dl>`);return;}try{if(action==='backup'){await api('/api/v1/backup-runs',{method:'POST',body:{projectId:item.projectId,clusterId:item.clusterId,policyId:item.id,idempotencyKey:idempotency('backup')}});toast('Backup run queued.');}else{await api(`/api/v1/backup-policies/${encodeURIComponent(item.id)}/${action}`,{method:'POST',headers:{'If-Match':`"${item.revision}"`},body:{}});toast(action==='disable'?'Backup schedule disabled.':'Backup schedule enabled.');}await loadFleet();}catch(error){toast(error.message,'error');}};
$('#data-protection-run-grid').onclick=async event=>{const button=event.target.closest('[data-dp-run-action]');if(!button)return;const item=state.dataProtectionRuns.find(row=>row.id===button.dataset.id);if(!item)return;const action=button.dataset.dpRunAction;if(action==='inspect'){showDetails('Data protection run',`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(item.id)}</dd><dt>Kind</dt><dd>${badge(item.kind)}</dd><dt>State</dt><dd>${badge(item.state)}</dd><dt>Reference</dt><dd class="technical">${esc(item.reference||'—')}</dd><dt>Evidence digest</dt><dd class="technical">${esc(item.evidenceDigest||'—')}</dd><dt>Recovery checkpoint</dt><dd class="technical">${esc(item.recoveryCheckpointId||'—')}</dd><dt>RPO seconds</dt><dd>${esc(item.rpoSeconds||0)}</dd><dt>RTO seconds</dt><dd>${esc(item.rtoSeconds||0)}</dd><dt>Requested by</dt><dd>${esc(item.requestedBy||'—')}</dd><dt>Approved by</dt><dd>${esc(item.approvedBy||'—')}</dd><dt>Error</dt><dd>${esc(item.lastError||'—')}</dd></dl>`);return;}try{if(action==='approve'){if(!await confirmAction('Approve restore','Approve this destructive restore request? The requester cannot approve their own restore.',true))return;await api(`/api/v1/restore-runs/${encodeURIComponent(item.id)}/approve`,{method:'POST',headers:{'If-Match':`"${item.revision}"`},body:{}});toast('Restore approved and queued.');}else{const endpoint=action==='drill'?'/api/v1/restore-drills':'/api/v1/restore-runs';if(action==='restore'&&!await confirmAction('Request restore','Create a destructive restore request from this verified backup? A different approver must approve it before execution.',true))return;await api(endpoint,{method:'POST',body:{projectId:item.projectId,clusterId:item.clusterId,policyId:item.policyId,backupRunId:item.id,idempotencyKey:idempotency(action==='drill'?'restore-drill':'restore')}});toast(action==='drill'?'Restore drill queued in an isolated namespace.':'Restore request created and waiting for independent approval.');}await loadFleet();}catch(error){toast(error.message,'error');}};
$('#recovery-checkpoint-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const cluster=state.clusters.map(row=>row.cluster||row).find(item=>item.id===$('#recovery-cluster').value);if(!cluster){toast('Select a cluster with current inventory.','error');return;}try{await api('/api/v1/recovery-checkpoints',{method:'POST',body:{projectId:cluster.projectId,clusterId:cluster.id,provider:$('#recovery-provider').value.trim(),reference:$('#recovery-reference').value.trim(),evidenceDigest:$('#recovery-evidence-digest').value.trim(),completedAt:new Date($('#recovery-completed-at').value).toISOString(),expiresAt:new Date($('#recovery-expires-at').value).toISOString()}});toast('Recovery checkpoint registered against current inventory.');$('#recovery-reference').value='';$('#recovery-evidence-digest').value='';await loadFleet();}catch(error){toast(error.message,'error');}};
$('#recovery-checkpoint-grid').onclick=async event=>{const button=event.target.closest('[data-recovery-action]');if(!button)return;const item=state.recoveryCheckpoints.find(row=>row.id===button.dataset.id);if(!item)return;if(button.dataset.recoveryAction==='inspect'){showDetails('Recovery checkpoint',`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(item.id)}</dd><dt>State</dt><dd>${badge(item.state)}</dd><dt>Cluster</dt><dd class="technical">${esc(item.clusterId)}</dd><dt>Provider</dt><dd>${esc(item.provider)}</dd><dt>Reference</dt><dd class="technical">${esc(item.reference)}</dd><dt>Evidence digest</dt><dd class="technical">${esc(item.evidenceDigest)}</dd><dt>Inventory digest</dt><dd class="technical">${esc(item.inventoryDigest)}</dd><dt>Completed</dt><dd>${formatDate(item.completedAt)}</dd><dt>Expires</dt><dd>${formatDate(item.expiresAt)}</dd></dl>`);return;}if(!await confirmAction('Revoke recovery checkpoint',`Revoke ${item.reference}? Campaigns that have not started must revalidate with new recovery evidence.`,true))return;try{await api(`/api/v1/recovery-checkpoints/${item.id}/revoke`,{method:'POST',headers:{'If-Match':`"${item.revision}"`},body:{}});toast('Recovery checkpoint revoked.');await loadFleet();}catch(error){toast(error.message,'error');}};
$('#fleet-project').onchange=loadFleet;
$('#reliability-incident-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const projectId=$('#fleet-project').value;if(!projectId){toast('Select a project first.','error');return;}try{await api('/api/v1/reliability/incidents',{method:'POST',body:{projectId,clusterId:$('#reliability-incident-cluster').value,service:$('#reliability-incident-service').value.trim(),severity:$('#reliability-incident-severity').value}});toast('Reliability incident created.');$('#reliability-incident-service').value='';await loadFleet();}catch(error){toast(error.message,'error');}};
$('#reliability-incident-grid').onclick=async event=>{const button=event.target.closest('[data-reliability-incident-action]');if(!button)return;const item=(state.reliabilityIncidents||[]).find(row=>row.id===button.dataset.id);if(!item)return;try{if(button.dataset.reliabilityIncidentAction==='acknowledge'){await api(`/api/v1/reliability/incidents/${encodeURIComponent(item.id)}/acknowledge`,{method:'POST',headers:{'If-Match':`"${item.revision}"`},body:{}});toast('Incident acknowledged.');}else{const values=await askFields('Resolve incident',[{name:'resolutionSummary',label:'Resolution summary',type:'text',value:''}],'Resolve');if(!values?.resolutionSummary?.trim())return;await api(`/api/v1/reliability/incidents/${encodeURIComponent(item.id)}/resolve`,{method:'POST',headers:{'If-Match':`"${item.revision}"`},body:{resolutionSummary:values.resolutionSummary.trim()}});toast('Incident resolved.');}await loadFleet();}catch(error){toast(error.message,'error');}};
$('#reliability-slo-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const projectId=$('#fleet-project').value;if(!projectId){toast('Select a project first.','error');return;}try{await api('/api/v1/reliability/slo-policies',{method:'POST',body:{projectId,clusterId:$('#reliability-slo-cluster').value,name:$('#reliability-slo-name').value.trim(),objectiveBasisPoints:Number($('#reliability-slo-objective').value),windowSeconds:Number($('#reliability-slo-window').value),observationIntervalSeconds:Number($('#reliability-slo-interval').value)}});toast('SLO policy created.');$('#reliability-slo-name').value='';await loadFleet();}catch(error){toast(error.message,'error');}};
$('#reliability-slo-grid').onclick=async event=>{const button=event.target.closest('[data-reliability-slo-action="revise"]');if(!button)return;const policy=(state.reliabilitySLOPolicies||[]).find(row=>row.id===button.dataset.id);if(!policy)return;const values=await askFields('Revise SLO policy',[{name:'objectiveBasisPoints',label:'Objective (basis points)',type:'number',value:policy.objectiveBasisPoints},{name:'windowSeconds',label:'Window seconds',type:'number',value:policy.windowSeconds},{name:'observationIntervalSeconds',label:'Observation interval',type:'number',value:policy.observationIntervalSeconds}],'Create revision');if(!values)return;try{await api('/api/v1/reliability/slo-policies',{method:'POST',headers:{'If-Match':`"${policy.revision}"`},body:{predecessorId:policy.id,objectiveBasisPoints:Number(values.objectiveBasisPoints),windowSeconds:Number(values.windowSeconds),observationIntervalSeconds:Number(values.observationIntervalSeconds)}});toast('SLO revision created.');await loadFleet();}catch(error){toast(error.message,'error');}};
$('#fleet-group-form').onsubmit=async event=>{event.preventDefault();if(!event.currentTarget.reportValidity())return;const clusterIds=$$('#fleet-clusters option:checked').map(option=>option.value);if(!clusterIds.length){toast('Select at least one connected cluster.','error');return;}try{await api('/api/v1/fleet-groups',{method:'POST',headers:{'Idempotency-Key':idempotency('fleet')},body:{projectId:$('#fleet-project').value,name:$('#fleet-name').value.trim(),displayName:$('#fleet-display-name').value.trim(),clusterIds}});toast('Fleet group created.');event.currentTarget.reset();await loadFleet();}catch(error){toast(error.message,'error');}};
$('#fleet-group-grid').onclick=async event=>{
  const button=event.target.closest('[data-fleet-action]'); if(!button)return;
  const group=state.fleetGroups.find(item=>item.id===button.dataset.id); if(!group)return;
  if(button.dataset.fleetAction==='drift'){try{const organization=$('#drift-git-organization').value.trim(),repository=$('#drift-git-repository').value.trim(),branch=$('#drift-git-branch').value.trim()||'main';if((organization&&!repository)||(!organization&&repository)){toast('Enter both Git organization and repository, or leave both empty.','error');return;}const body={projectId:group.projectId,fleetGroupId:group.id};if(organization&&repository)body.git={organization,repository,branch};await api('/api/v1/drift-scans',{method:'POST',headers:{'Idempotency-Key':idempotency('drift')},body});toast(organization?'Three-way Git + live drift scan queued.':'Live baseline drift scan queued.');await loadFleet();}catch(error){toast(error.message,'error');}return;}
  const targetOptions=state.baselines.filter(item=>item.id==='secure-namespace-foundation'&&Array.isArray(item.upgradeFrom)&&item.upgradeFrom.length>0).map(item=>({value:item.version,label:`${item.displayName} · ${item.version} · from ${item.upgradeFrom.join(', ')}`}));
  if(!targetOptions.length){toast('No upgrade-capable baseline revision is currently available for this fleet.','error');return;}
  const fields=[{name:'targetVersion',label:'Target baseline version',type:'select',options:targetOptions},{name:'maintenanceWindowStart',label:'Maintenance window start',type:'datetime-local',value:localDateTimeValue(new Date(Date.now()+5*60000))},{name:'maintenanceWindowEnd',label:'Maintenance window end',type:'datetime-local',value:localDateTimeValue(new Date(Date.now()+2*3600000))},{name:'canaryCount',label:'Canary clusters',type:'number',value:1,min:1,max:group.clusterIds.length},{name:'waveSize',label:'Wave size',type:'number',value:Math.min(2,group.clusterIds.length),min:1,max:group.clusterIds.length},{name:'haltAfterFailures',label:'Halt after failures',type:'number',value:1,min:1,max:group.clusterIds.length}];
  for(const clusterId of group.clusterIds){const cluster=(state.clusters.map(row=>row.cluster||row)).find(item=>item.id===clusterId);const eligible=state.recoveryCheckpoints.filter(item=>item.projectId===group.projectId&&item.clusterId===clusterId&&item.state==='VERIFIED'&&item.inventoryDigest===cluster?.inventoryDigest&&new Date(item.expiresAt)>new Date()).sort((a,b)=>new Date(b.completedAt)-new Date(a.completedAt));if(!eligible.length){toast(`Register a valid recovery checkpoint for ${cluster?.displayName||clusterId} first.`,'error');return;}fields.push({name:`checkpoint_${clusterId}`,label:`Recovery checkpoint · ${cluster?.displayName||clusterId}`,type:'select',options:eligible.map(item=>({value:item.id,label:`${item.provider} · ${item.reference} · expires ${formatDate(item.expiresAt)}`}))});}
  const values=await askFields('Create safe upgrade campaign',fields,'Create campaign'); if(!values)return;
  const recoveryCheckpointIds=group.clusterIds.map(id=>values[`checkpoint_${id}`]);
  if(!await confirmAction('Review upgrade campaign',`Create a campaign for ${group.clusterIds.length} cluster(s) targeting ${values.targetVersion}, canary ${values.canaryCount}, wave size ${values.waveSize}, halt after ${values.haltAfterFailures} failure(s), with ${recoveryCheckpointIds.length} recovery checkpoint(s)? The campaign still requires independent approval before rollout.`))return;
  try{await api('/api/v1/upgrade-campaigns',{method:'POST',headers:{'Idempotency-Key':idempotency('upgrade')},body:{projectId:group.projectId,fleetGroupId:group.id,baselineId:'secure-namespace-foundation',targetVersion:values.targetVersion,canaryCount:values.canaryCount,waveSize:values.waveSize,haltAfterFailures:values.haltAfterFailures,maintenanceWindowStart:new Date(values.maintenanceWindowStart).toISOString(),maintenanceWindowEnd:new Date(values.maintenanceWindowEnd).toISOString(),recoveryCheckpointIds}});toast('Upgrade campaign created with recovery and maintenance safety context.');await loadFleet();}catch(error){toast(error.message,'error');}
};
$('#drift-scan-grid').onclick=async event=>{const button=event.target.closest('[data-drift-action]');if(!button)return;if(button.dataset.driftAction==='adopt-git'){if(!await confirmAction('Adopt trusted external Git revision','This does not overwrite Git or live state. It only records the already-applied, platform-signed Git revision as the new drift base.'))return;try{await api(`/api/v1/drift-scans/${button.dataset.scanId}/adopt-git`,{method:'POST',body:{clusterId:button.dataset.clusterId}});toast('Trusted external Git revision adopted without overwrite. Run a new drift scan to confirm convergence.');await loadFleet();}catch(error){toast(error.message,'error');}return;}if(button.dataset.driftAction==='remediate-finding'){if(!await confirmAction('Queue drift remediation','This creates a durable, idempotent operation bound to this exact drift finding. It does not automatically overwrite Git.'))return;try{const result=await api(`/api/v1/drift-scans/${button.dataset.scanId}/targets/${button.dataset.clusterId}/findings/${button.dataset.fingerprint}/remediate`,{method:'POST',headers:{'Idempotency-Key':idempotency('drift-remediation')}});toast(`Remediation operation ${result.operation?.state||'QUEUED'}: ${result.operation?.id||''}`);await loadFleet();}catch(error){toast(error.message,'error');}}};
$('#upgrade-campaign-grid').onclick=async event=>{const button=event.target.closest('[data-upgrade-action]');if(!button)return;const campaign=state.upgradeCampaigns.find(item=>item.id===button.dataset.id);if(!campaign)return;const action=button.dataset.upgradeAction;if(action==='inspect'){showDetails('Upgrade campaign',`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(campaign.id)}</dd><dt>Authority</dt><dd class="technical">${esc(state.day2CampaignEngine?.authority||'GENERALIZED_DAY2_CAMPAIGN_ENGINE_V1')}</dd><dt>State</dt><dd>${badge(campaign.state)}</dd><dt>Baseline</dt><dd class="technical">${esc(campaign.baselineId)}@${esc(campaign.targetVersion)}</dd><dt>Current wave</dt><dd>${esc(campaign.currentWave||0)}</dd><dt>Maintenance window</dt><dd>${formatDate(campaign.maintenanceWindowStart)} → ${formatDate(campaign.maintenanceWindowEnd)}</dd><dt>Plan context</dt><dd class="technical">${esc(campaign.planContextDigest||'—')}</dd><dt>Plan expires</dt><dd>${formatDate(campaign.planExpiresAt)}</dd><dt>Recovery checkpoints</dt><dd class="technical">${esc((campaign.recoveryCheckpointIds||[]).join(', ')||'—')}</dd><dt>Pause count</dt><dd>${esc(campaign.pauseCount||0)}</dd><dt>Paused by / at</dt><dd>${esc(campaign.pausedBy||'—')} · ${formatDate(campaign.pausedAt)}</dd><dt>Cancel requested</dt><dd>${esc(campaign.cancelRequestedBy||'—')} · ${formatDate(campaign.cancelRequestedAt)}</dd><dt>Cancelled by / at</dt><dd>${esc(campaign.cancelledBy||'—')} · ${formatDate(campaign.cancelledAt)}</dd><dt>Control reason</dt><dd>${esc(campaign.controlReason||'—')}</dd><dt>Summary</dt><dd>${esc(campaign.summary||'—')}</dd><dt>Error</dt><dd>${esc(campaign.lastError||'—')}</dd></dl>`);return;}if(action==='approve'&&!await confirmAction('Approve upgrade campaign',`Approve rollout of ${campaign.baselineId}@${campaign.targetVersion} to ${(campaign.targets||[]).length} clusters?`))return;
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
    setProjectOptions($('#tenant-project'),visibleProjects);
    const projectId=$('#tenant-project').value;
    const clusters=clusterRows.map(row=>row.cluster||row).filter(cluster=>!projectId||cluster.projectId===projectId);
    setOptions($('#tenant-cluster'),clusters,item=>item.id,item=>`${item.displayName} · ${item.kubernetesVersion||'version pending'}`,'Connect a cluster first');
    const planValues=Array.isArray(plans)?plans:Object.values(plans||{});
    setOptions($('#tenant-plan'),planValues,item=>item.name,item=>`${item.name} · CPU ${item.quota?.['requests.cpu']||'—'} · RAM ${item.quota?.['requests.memory']||'—'} · ${item.storage?.requestQuota||'—'} storage · ${item.backup?.provider||'no backup'}`,'No tenant plans');
    prerequisite($('#tenants-prerequisite'),organizations.length>0&&visibleProjects.length>0,'An organization and project are required before tenant provisioning.','workspace','Create organization and project records');
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

function mcpMutationDescriptor(tool){
  const map={
    operation_cancel:{family:'Operation control',risk:'MEDIUM',approval:false,detail:'Revision-guarded cancellation through the durable operation state machine.'},
    drift_scan_request:{family:'Assurance',risk:'LOW',approval:false,detail:'Observational live drift scan only; it cannot remediate findings.'},
    runtime_verification_request:{family:'Assurance',risk:'LOW',approval:false,detail:'Creates a digest-pinned runtime verification task against one successful baseline deployment.'},
    cluster_maintenance_request:{family:'Day-2 maintenance',risk:'HIGH',approval:true,detail:'High-impact maintenance request stops at independent approval; requester cannot self-approve.'},
    upgrade_campaign_request:{family:'Fleet upgrade',risk:'HIGH',approval:true,detail:'High-impact canary/wave upgrade request requires recovery checkpoints and stops at independent approval.'}
  };
  return map[tool]||{family:'Delegated operation',risk:'MEDIUM',approval:false,detail:'Allow-listed product mutation with project/RBAC/idempotency/revision/audit enforcement.'};
}

function renderMCPHumanDelegation(){
  const target=$('#ai-mcp-human-connection-status'); if(!target)return;
  const model=state.mcpDelegationArchitecture||{};
  const oauthReady=String(model.status||'').includes('OAUTH_DISCOVERY_AND_AUDIENCE_SOURCE_IMPLEMENTED');
  const steps=['Sign in with organization account','Choose organization or project','Choose friendly access','Review and confirm','Follow jobs and results'];
  target.innerHTML=`<div class="journey-strip">${steps.map((step,index)=>`<div class="journey-step"><span>${index+1}</span><strong>${esc(localizeDynamicText(step))}</strong></div>`).join('')}</div><div class="${oauthReady?'success-banner':'warning-banner'}"><strong>${esc(localizeDynamicText(oauthReady?'OAuth connection foundation':'Connection setup is not enabled yet'))}</strong><p>${esc(localizeDynamicText('OAuth discovery and dedicated MCP audience are implemented. Revocable delegation grants, trusted-client registration and consent management are still required before human connections can be enabled.'))}</p></div><details><summary>${esc(localizeDynamicText('Advanced connection details'))}</summary><div class="resource-details">${detailRow('Authority',model.authority||'—',true)}${detailRow('Protocol',model.protocolVersion||'—',true)}${detailRow('Resource server',model.resourceServer||'/mcp',true)}${detailRow('OAuth metadata',model.protectedResourceMetadata||'/.well-known/oauth-protected-resource',true)}${detailRow('Token audience',model.tokenAudience||'platform-mcp',true)}${detailRow('Authorization',model.authorizationAuthority||'Keycloak',true)}</div></details>`;
}

function renderAIControlAuthority(){
  const cap=state.aiCapabilities||{},target=$('#ai-control-capabilities');
  if(target){
    const counts=cap.counts||{},routeCount=Number(cap.routeCount||0),callable=Number(cap.aiCallableRoutes||0),mutations=Number(cap.durableMutationRoutes||0),excluded=Number(counts['security-excluded']||0);
    const coverage=Number(cap.routeDispositionCoveragePercent||0),durable=Number(cap.durableMutationCoveragePercent||0);
    target.innerHTML=`<div class="metric-grid compact-metrics"><article class="metric-card"><strong>${esc(coverage)}%</strong><span>Route disposition</span><small>${esc(routeCount)} / ${esc(routeCount)} stable routes mapped</small></article><article class="metric-card"><strong>${esc(callable)}</strong><span>AI-callable routes</span><small>${esc(excluded)} intentionally protected</small></article><article class="metric-card"><strong>${esc(durable)}%</strong><span>Durable mutations</span><small>${esc(mutations)} / ${esc(mutations)} operate + administration routes</small></article></div><div class="resource-details">${detailRow('Read routes',counts['tool-read']||0)}${detailRow('Operate routes',counts['tool-operate']||0)}${detailRow('Administration routes',counts['tool-admin']||0)}${detailRow('Protected routes',excluded)}${detailRow('Idempotency',cap.idempotencyRequired?'REQUIRED':'NOT ENFORCED')}${detailRow('Retry policy',cap.expiredInFlightPolicy||'—',true)}${detailRow('Arbitrary route',cap.arbitraryRouteAllowed?'ALLOWED':'BLOCKED')}${detailRow('Raw credentials',cap.rawCredentialAccess?'ALLOWED':'BLOCKED')}</div><div class="inline-summary"><strong>Safety boundary:</strong> AI cannot decide PASS or Physical PASS. Administration tools require human ADMINISTRATION delegation; raw secrets, shell/SSH/SQL and self-delegation remain outside the MCP action surface.</div>`;
  }
  const jobsTarget=$('#ai-control-jobs'); if(!jobsTarget)return;
  const jobs=(state.aiControlJobs?.items||[]).slice(0,25);
  if(!jobs.length){jobsTarget.innerHTML=emptyState('No AI control jobs','No AI-triggered mutation is visible in the current organization/project scope.');return;}
  const rows=jobs.map(job=>tableRow([
    tableCell(`<span class="cell-title technical">${esc(job.toolName||job.action||'—')}</span><span class="cell-meta">${esc(job.family||'—')} · ${esc(job.method||'—')}</span>`),
    tableCell(`${badge(job.state||'UNKNOWN')}<span class="cell-meta">attempt ${esc(job.attempt||0)}</span>`),
    tableCell(`<span class="cell-title">${esc(job.actorId||'—')}</span><span class="cell-meta">${esc(job.authentication||'—')} · ${esc(job.delegationProfile||'—')}</span>`),
    tableCell(`<span class="cell-title technical">${esc(job.projectId||job.organizationId||'platform')}</span><span class="cell-meta">${esc(job.oauthClientId||'no client id')}</span>`),
    tableCell(`<span class="technical">${shortDigest(job.requestDigest)}</span><span class="cell-meta technical">${shortDigest(job.responseDigest)}</span>`),
    tableCell(formatDate(job.createdAt),'timestamp')
  ]));
  jobsTarget.innerHTML=dataTable('Durable AI control jobs',[{label:'Action'},{label:'State'},{label:'Actor / delegation'},{label:'Scope / client'},{label:'Request / result digest'},{label:'Created',className:'timestamp'}],rows,'No AI control jobs','AI mutations appear here only after the durable job is recorded.',{key:'ai-control-jobs'});
}

async function reloadAIControlJobs(){
  try{state.aiControlJobs=await api('/api/v1/ai/control-jobs');renderAIControlAuthority();}
  catch(error){const target=$('#ai-control-jobs');if(target)target.innerHTML=errorState(error.message);}
}

function renderAIRuntimeAndAccess(){
  const policy=state.aiPolicy||{},guide=state.aiGuide||{},mcp=guide.mcp||{};
  const runtime=$('#ai-runtime-details');
  if(runtime){
    const last=latest(state.aiRuns||[])[0];
    runtime.innerHTML=`<div class="resource-details">${detailRow('Runtime authority',policy.runtimeAuthority||'—',true)}${detailRow('Configuration',policy.enabled?badge('CONFIGURED'):badge('DISABLED'))}${detailRow('Provider',esc(policy.provider||'none'))}${detailRow('Model',esc(policy.model||'—'))}${detailRow('Input ceiling',`${esc(policy.maxInputBytes||0)} bytes`)}${detailRow('Output ceiling',`${esc(policy.maxOutputTokens||0)} tokens`)}${detailRow('Redaction',policy.redactionRequired?'REQUIRED':'UNKNOWN')}${detailRow('Latest durable advisory',last?formatDate(last.createdAt):'None recorded')}</div><div class="inline-summary"><strong>Authority:</strong> diagnosis is advisory · no PASS / Physical PASS. Allow-listed MCP mutations require separate mcp.operate authority, project scope, revision guards and durable audit. Provider reachability is evaluated only by an actual bounded diagnosis request.</div>`;
  }
  const access=$('#ai-mcp-access');
  if(access){
    const tools=mcp.tools||[],mutating=mcp.mutatingTools||[];
    access.innerHTML=`<div class="resource-details">${detailRow('Endpoint',mcp.path||'/mcp',true)}${detailRow('Protocol',mcp.protocol||'2026-07-28',true)}${detailRow('Transport',mcp.transport||'streamable-http')}${detailRow('Read scope',mcp.permission||'mcp.read',true)}${detailRow('Operation scope',mcp.operationPermission||'mcp.operate',true)}${detailRow('Diagnosis scope','ai.diagnose',true)}${detailRow('Mutation tools',mutating.length?String(mutating.length):'NONE')}</div><div class="inline-summary"><strong>Delegation boundary:</strong> read-only by default. Mutation tools are allow-listed product operations; normal role/project authorization, expected revision and durable audit remain mandatory.</div><details open><summary>Read-only tools (${tools.length})</summary><div class="activity-list">${tools.map(tool=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">✓</span><div><strong class="technical">${esc(tool)}</strong><small>Authenticated capability context · project authorization is rechecked for project resources.</small></div></div>${badge('READ ONLY')}</div>`).join('')}</div></details>${mutating.length?`<details open><summary>Delegated operation tools (${mutating.length})</summary><div class="activity-list">${mutating.map(tool=>{const meta=mcpMutationDescriptor(tool);return `<div class="activity-item"><div class="activity-main"><span class="check-icon">↳</span><div><strong class="technical">${esc(tool)}</strong><small>${esc(meta.family)} · ${esc(meta.detail)}</small></div></div><div class="resource-meta">${badge(meta.risk)}${badge(meta.approval?'APPROVAL GATED':'DELEGATED')}</div></div>`}).join('')}</div></details>`:''}`;
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

function aiAgentLastActivity(account){const actor=`service-account:${account.id}`;const rows=(state.securityAudit||[]).filter(item=>item.actorId===actor).sort((a,b)=>new Date(b.occurredAt)-new Date(a.occurredAt));return rows[0]||null;}
function renderAIAgentAccess(){const grid=$('#ai-agent-access-grid');if(!grid)return;const accounts=state.aiServiceAccounts||[];if(!accounts.length){grid.innerHTML=emptyState('No scoped agent identities','Select an organization with service accounts or create one from Organizations & projects.');return;}grid.innerHTML=accounts.map(account=>{const tokens=state.aiAPITokens?.[account.id]||[],activity=aiAgentLastActivity(account),scope=account.projectId?`Project · ${account.projectId}`:'Organization-wide';const tokenRows=tokens.map(token=>{const effective=tokenEffectiveState(token);return `<div class="activity-item"><div class="activity-main"><span class="check-icon">⌁</span><div><strong class="technical">${esc(token.tokenPrefix)}</strong><small>${esc((token.permissions||[]).join(' + '))} · expires ${esc(formatDate(token.expiresAt))}</small></div></div><div class="resource-meta">${badge(effective)}${effective==='ACTIVE'?`<button class="secondary small-button" data-ai-agent-token-action="rotate" data-account-id="${esc(account.id)}" data-token-id="${esc(token.id)}">Rotate</button><button class="danger small-button" data-ai-agent-token-action="revoke" data-account-id="${esc(account.id)}" data-token-id="${esc(token.id)}">Revoke</button>`:''}</div></div>`}).join('')||'<small>No API tokens issued.</small>';return `<article class="resource-card"><div class="resource-header"><div><h3>${esc(account.displayName)}</h3><div class="resource-meta">${badge(account.state)} ${badge(account.productRole)}</div></div></div><div class="resource-details">${detailRow('Scope',scope,true)}${detailRow('Latest auth activity',activity?`${formatDate(activity.occurredAt)} · ${activity.outcome||activity.decision||'recorded'}`:'No loaded security-audit activity')}${detailRow('MCP operate',tokens.some(t=>(t.permissions||[]).includes('mcp.operate'))?'DELEGATED':'NOT GRANTED')}${detailRow('MCP read',tokens.some(t=>(t.permissions||[]).includes('mcp.read'))?'GRANTED':'NOT GRANTED')}</div><details open><summary>API tokens · ${tokens.length}</summary><div class="activity-list">${tokenRows}</div></details>${account.state==='ACTIVE'?`<div class="resource-actions"><button class="danger small-button" data-ai-agent-account-revoke="${esc(account.id)}">Revoke service account</button></div>`:''}</article>`}).join('');}
async function loadAIAgentAccess(){const select=$('#ai-agent-organization');if(!select)return;const orgs=state.organizations?.length?state.organizations:await softApi('/api/v1/organizations',[],'organizations');state.organizations=orgs;const previous=select.value;setOptions(select,orgs,item=>item.id,item=>item.displayName||item.name,'No organizations');if(previous&&orgs.some(o=>o.id===previous))select.value=previous;if(!select.value){state.aiServiceAccounts=[];state.aiAPITokens={};renderAIAgentAccess();return;}try{const accounts=await api(`/api/v1/service-accounts?organizationId=${encodeURIComponent(select.value)}`);state.aiServiceAccounts=accounts;state.aiAPITokens={};await Promise.all(accounts.map(async account=>{state.aiAPITokens[account.id]=await api(`/api/v1/service-accounts/${encodeURIComponent(account.id)}/tokens`);}));if(mayAdministerIdentityAuthority())state.securityAudit=await softApi('/api/v1/security-audit-events?limit=200',state.securityAudit||[],'security audit');renderAIAgentAccess();}catch(error){$('#ai-agent-access-grid').innerHTML=errorState(error.message);}}
$('#ai-agent-organization').onchange=loadAIAgentAccess;
$('#ai-agent-access-grid').onclick=async event=>{const revokeAccount=event.target.closest('[data-ai-agent-account-revoke]');if(revokeAccount){const account=state.aiServiceAccounts.find(a=>a.id===revokeAccount.dataset.aiAgentAccountRevoke);if(!account||!await confirmAction('Revoke agent identity',`Revoke ${account.displayName} and every active token?`,true))return;try{await api(`/api/v1/service-accounts/${account.id}/revoke`,{method:'POST',headers:{'If-Match':`"${account.revision}"`,'X-Confirm-Revoke':'revoke-service-account'}});toast('Agent identity revoked.');await loadAIAgentAccess();}catch(error){toast(error.message,'error');}return;}const button=event.target.closest('[data-ai-agent-token-action]');if(!button)return;const account=state.aiServiceAccounts.find(a=>a.id===button.dataset.accountId),token=(state.aiAPITokens?.[button.dataset.accountId]||[]).find(t=>t.id===button.dataset.tokenId);if(!account||!token)return;if(button.dataset.aiAgentTokenAction==='revoke'){if(!await confirmAction('Revoke agent token',`Immediately revoke ${token.tokenPrefix}?`,true))return;try{await api(`/api/v1/service-accounts/${account.id}/tokens/${token.id}/revoke`,{method:'POST',headers:{'If-Match':`"${token.revision}"`,'X-Confirm-Revoke':'revoke-api-token'}});toast('Agent token revoked.');await loadAIAgentAccess();}catch(error){toast(error.message,'error');}return;}const options=apiTokenPermissionProfiles(account),values=await askFields('Rotate agent token',[{name:'hours',label:'New expiry in hours',type:'number',value:24,min:1,max:8784},{name:'permission',label:'Permission profile',type:'select',options,value:apiTokenPermissionProfileValue(token.permissions)}],'Review rotation');if(!values)return;if(!await confirmAction('Rotate agent token',`Rotate ${token.tokenPrefix}? The old token is invalidated.`,true))return;try{const response=await api(`/api/v1/service-accounts/${account.id}/tokens/${token.id}/rotate`,{method:'POST',headers:{'If-Match':`"${token.revision}"`,'X-Confirm-Rotate':'rotate-api-token','Idempotency-Key':idempotency('ai-agent-token-rotate')},body:{expiresAt:new Date(Date.now()+Number(values.hours)*3600000).toISOString(),permissions:apiTokenPermissionsFromProfile(values.permission)}});showOneTimeAPIToken('Agent token rotated',response);await loadAIAgentAccess();}catch(error){toast(error.message,'error');}};

async function loadAI(){
  try{
    const [policy,guide,projects,operations,clusters,runs,mcpDelegationArchitecture,aiCapabilities,aiControlJobs]=await Promise.all([
      softApi('/api/v1/ai/policy',{},'AI policy'), softApi('/api/v1/lab/guide',{},'lab guide'), softApi('/api/v1/projects',[],'projects'), softApi('/api/v1/operations?limit=200',[],'operations'), softApi('/api/v1/clusters',[],'clusters'), softApi('/api/v1/ai/runs',[],'AI runs'), softApi('/api/v1/mcp/delegation-architecture',{},'MCP delegation architecture'), softApi('/api/v1/ai/capabilities',{},'AI control capabilities'), softApi('/api/v1/ai/control-jobs',{items:[]},'AI control jobs')
    ]);
    state.aiPolicy=policy; state.aiGuide=guide; state.projects=projects; state.operations=operations; state.clusters=clusters; state.aiRuns=runs; state.mcpDelegationArchitecture=mcpDelegationArchitecture; state.aiCapabilities=aiCapabilities; state.aiControlJobs=aiControlJobs;
    $('#ai-policy-summary').innerHTML=[
      ['Runtime',policy.enabled?'ENABLED':'DISABLED',policy.provider||'none'],['Model',policy.model||'—','provider-selected'],['Input budget',policy.maxInputBytes||0,'bytes after redaction'],['Output budget',policy.maxOutputTokens||0,'tokens max'],['Authority','ADVISORY ONLY','PASS / Physical PASS: never']
    ].map(([label,value,detail])=>`<article class="metric-card"><strong>${esc(value)}</strong><span>${esc(label)}</span><small>${esc(detail)}</small></article>`).join('');
    const banner=$('#ai-runtime-banner');
    if(banner){banner.hidden=!!policy.enabled;banner.innerHTML=policy.enabled?'':'<strong>AI runtime disabled</strong><p>No model provider is configured. Deterministic platform, Lab and certification workflows remain available; AI diagnosis is intentionally unavailable.</p>';}
    const diagnosisButton=$('#ai-diagnosis-form button[type="submit"]'); if(diagnosisButton)diagnosisButton.disabled=!policy.enabled;
    const projectSelect=$('#ai-project'); const selected=projectSelect?.value||'';
    setProjectOptions(projectSelect,projects,item=>item.displayName||item.name||item.id,'Select project');
    if(!state.globalScope.projectId&&selected&&projects.some(p=>p.id===selected))projectSelect.value=selected;
    const historyFilter=$('#ai-run-project-filter'),historySelected=historyFilter?.value||'';
    if(historyFilter){historyFilter.innerHTML='<option value="">All accessible projects</option>'+projects.map(p=>`<option value="${esc(p.id)}">${esc(p.displayName||p.name||p.id)}</option>`).join('');if(historySelected&&projects.some(p=>p.id===historySelected))historyFilter.value=historySelected;}
    syncAIResourceOptions();
    renderAIControlAuthority(); renderAIRuntimeAndAccess(); renderMCPHumanDelegation(); renderAIUsageSummary(); renderAIRunHistory(); renderAILatestDiagnosis(); await loadAIAgentAccess();
  }catch(error){toast(error.message,'error');}
}

$('#ai-project').onchange=syncAIResourceOptions;
$('#ai-resource-type').onchange=syncAIResourceOptions;
$('#ai-run-project-filter').onchange=renderAIRunHistory;
$('#ai-control-jobs-refresh').onclick=reloadAIControlJobs;
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
    if(guide.authority && guide.authority!=='LAB_CERTIFICATION_MATRIX_V2') throw new Error('Unexpected lab guide authority.');
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
    $('#lab-mcp').innerHTML=`<div class="resource-details">${detailRow('Endpoint',mcp.path||mcp.endpoint||'/mcp')}${detailRow('Protocol',mcp.protocol||mcp.protocolVersion||'—')}${detailRow('Transport',mcp.transport||'—')}${detailRow('Default authority','READ ONLY')}${detailRow('Operation scope',mcp.operationPermission||'mcp.operate')}</div><details open><summary>Read tools</summary><div class="activity-list">${(mcp.tools||[]).map(tool=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">✓</span><div><strong class="technical">${esc(tool.name||tool)}</strong><small>${esc(tool.description||'authoritative read-only resource')}</small></div></div>${badge('READ ONLY')}</div>`).join('')}</div></details>${(mcp.mutatingTools||[]).length?`<details><summary>Delegated operation tools</summary><div class="activity-list">${mcp.mutatingTools.map(tool=>{const name=tool.name||tool,meta=mcpMutationDescriptor(name);return `<div class="activity-item"><div class="activity-main"><span class="check-icon">↳</span><div><strong class="technical">${esc(name)}</strong><small>${esc(meta.family)} · ${esc(meta.detail)}</small></div></div><div class="resource-meta">${badge(meta.risk)}${badge(meta.approval?'APPROVAL GATED':'DELEGATED')}</div></div>`}).join('')}</div></details>`:''}<p class="inline-summary">External clients authenticate through the normal Platform API boundary and send <span class="technical">MCP-Protocol-Version: ${esc(mcp.protocol||mcp.protocolVersion||'2026-07-28')}</span>. MCP cannot certify Physical PASS or bypass product approval boundaries.</p>`;
    restoreDataTableSortPreferences($('#lab'));
  }catch(error){toast(error.message,'error');}
}

function renderAutopilotCampaign(){const target=$('#autopilot-campaign-status'),item=state.autopilotStatus;if(!target)return;if(!item?.configured){target.innerHTML=emptyState('Autopilot evidence not configured',item?.message||'Set PLATFORM_FACTORY_AUTOPILOT_STATE_DIR on the local platform API instance to expose sanitized local campaign evidence.');return;}if(!item.available){target.innerHTML=emptyState('No campaign evidence yet',item.message||'Run the checkpoint-safe Autopilot to create the derived campaign report.');return;}const completed=(item.stageResults||[]).filter(row=>row.status==='PASS').length;target.innerHTML=`<div class="metric-grid"><div class="metric"><span>Status</span><strong>${esc(item.status||'—')}</strong></div><div class="metric"><span>Stage</span><strong>${esc(item.nextIndex||0)} / ${esc(item.stageCount||0)}</strong></div><div class="metric"><span>Repairs</span><strong>${esc(item.repairCount||0)}</strong></div><div class="metric"><span>Completed loaded</span><strong>${completed}</strong></div></div><div class="resource-details">${detailRow('Phase',item.phase||'—')}${detailRow('Current stage',item.currentStage||'—',true)}${detailRow('Specialist',item.currentSpecialist||'—')}${detailRow('Active process',item.activeProcess||'none',true)}${detailRow('Resume eligible',item.resumeEligible?'YES':'NO')}${detailRow('Updated',formatDate(item.updatedAt))}</div>${item.lastFailure?`<div class="warning-banner"><strong>Latest failure · ${esc(item.lastFailure.stage||'unknown')}</strong><p>${esc(item.lastFailure.reason||item.lastFailure.status||'Failure recorded')} · specialist ${esc(item.lastFailure.specialist||'—')} · fingerprint <span class="technical">${esc(item.lastFailure.fingerprint||'—')}</span></p></div>`:''}<details><summary>Recent stage evidence · ${(item.stageResults||[]).length}</summary><div class="activity-list">${(item.stageResults||[]).slice(-12).reverse().map(row=>`<div class="activity-item"><div class="activity-main"><span class="check-icon">${row.status==='PASS'?'✓':row.status==='FAIL'?'!':'•'}</span><div><strong>${esc(row.name)}</strong><small>${esc(row.specialist||'—')} · ${esc(row.elapsedSeconds||0)}s · <span class="technical">${esc(row.fingerprint||'—')}</span></small></div></div>${badge(row.status||'UNKNOWN')}</div>`).join('')}</div></details><div class="inline-summary">${esc(item.authority)} · derived local evidence · never Product or Physical authority</div>`;}
function supportScopeRows(profile){const scope=profile?.scope;if(scope==='project')return state.projects||[];if(scope==='cluster')return state.clusters||[];if(scope==='operation')return state.operations||[];return [];}
function renderSupportCenter(){const profileSelect=$('#support-center-profile'),scopeSelect=$('#support-center-scope');if(!profileSelect||!scopeSelect)return;const previous=profileSelect.value;profileSelect.innerHTML=(state.supportProfiles||[]).map(p=>`<option value="${esc(p.name)}">${esc(p.name)} · ${esc(p.description)}</option>`).join('');if(previous&&state.supportProfiles.some(p=>p.name===previous))profileSelect.value=previous;const profile=state.supportProfiles.find(p=>p.name===profileSelect.value),rows=supportScopeRows(profile),old=scopeSelect.value;scopeSelect.innerHTML=rows.map(item=>`<option value="${esc(item.id)}">${esc(item.displayName||item.name||item.kind||item.id)} · ${esc(item.id)}</option>`).join('');if(old&&rows.some(item=>item.id===old))scopeSelect.value=old;$('#support-center-scope-field').querySelector('span').textContent=profile?.scope?`${profile.scope[0].toUpperCase()+profile.scope.slice(1)} scope`:'Scope';}
$('#support-center-profile').onchange=renderSupportCenter;
$('#support-center-form').onsubmit=async event=>{event.preventDefault();const profile=state.supportProfiles.find(p=>p.name===$('#support-center-profile').value),id=$('#support-center-scope').value;if(!profile||!id){toast('Select a support scope.','error');return;}const body={profile:profile.name};body[profile.scope+'Id']=id;try{await downloadSupportBundle(body,'#support-center-status');toast('Verified support bundle downloaded.');}catch(error){toast(error.message,'error');}};


function queueLane(queueCenter,id){return (queueCenter?.lanes||[]).find(item=>item.id===id)||{};}
function renderOperationsQueueCenter(){
  const center=state.queueCenter||{},operationsLane=queueLane(center,'operations'),agentLane=queueLane(center,'agent-tasks'),notificationsLane=queueLane(center,'notifications'),outboxLane=queueLane(center,'outbox');
  const summary=$('#queue-center-summary'),grid=$('#queue-center-grid'),authority=$('#queue-center-authority');if(!summary||!grid||!authority)return;
  summary.innerHTML=[
    ['Operation pending',operationsLane.pending||0,`${operationsLane.executing||0} executing · ${operationsLane.retryWait||0} retry wait`],
    ['Operation attention',operationsLane.attention||0,`${operationsLane.expiredClaims||0} expired loaded leases`],
    ['Agent tasks',agentLane.pending||0,`${agentLane.executing||0} executing · ${agentLane.expiredClaims||0} expired · ${agentLane.retried||0} retried · max attempt ${agentLane.maxAttempt||0}${agentLane.oldestPendingAt?` · oldest pending ${formatDate(agentLane.oldestPendingAt)}`:''}`],
    ['Notification pending',(notificationsLane.pending||0)+(notificationsLane.retryWait||0),`${notificationsLane.executing||0} delivering · ${notificationsLane.deadLetter||0} dead-letter`],
    ['Outbox pending',outboxLane.pending||0,'transactional unpublished events']
  ].map(([label,value,detail])=>`<article class="metric-card"><strong>${esc(value)}</strong><span>${esc(label)}</span><small>${esc(detail)}</small></article>`).join('');
  const rows=(center.items||[]).map(item=>tableRow([
    tableCell(`<span class="cell-title">${esc(item.kind)}</span><span class="cell-meta technical">${esc(item.id)}</span>`),
    tableCell(`${badge(item.lane)} ${badge(item.state)}`,'status-cell'),
    tableCell(`<span class="cell-title">${esc(item.attempt||0)} / ${esc(item.maxAttempts||'—')}</span><span class="cell-meta technical">${esc(item.leaseOwner||'no active lease')}</span>`),
    tableCell(`${item.leaseExpiresAt?formatDate(item.leaseExpiresAt):'—'}${item.nextAttemptAt?`<span class="cell-meta">next ${formatDate(item.nextAttemptAt)}</span>`:''}`,'timestamp',item.leaseExpiresAt||item.nextAttemptAt||''),
    tableCell(`<span class="cell-title">${esc(item.lastError||'—')}</span><span class="cell-meta">updated ${esc(formatDate(item.updatedAt))}</span>`)
  ]));
  grid.innerHTML=dataTable('Queue work items',[{label:'Work item'},{label:'Lane / state'},{label:'Attempt / owner'},{label:'Lease / retry',className:'timestamp'},{label:'Last result'}],rows,'No queued work','No non-terminal durable operation or notification-delivery item is loaded in this scope. Agent-task details stay aggregate-only by design.',{key:'operations-queue-center'});
  const truncated=(center.lanes||[]).filter(l=>l.truncated).map(l=>l.id);
  authority.innerHTML=`<strong>${esc(center.authority||'OPERATIONS_QUEUE_CENTER_V1')}</strong> · ${esc(center.backend||'—')} · read-only · scope-before-limit · ${esc(center.limit||0)} item window${truncated.length?` · truncated lanes: ${esc(truncated.join(', '))}`:' · loaded lanes complete for this window'}`;
}
function renderProductLogCenter(){
  const result=state.productLogs||{},entries=result.entries||[],opSelect=$('#log-center-operation');if(!opSelect)return;
  const previous=opSelect.value;opSelect.innerHTML=`<option value="">All operations</option>${(state.operations||[]).map(op=>`<option value="${esc(op.id)}">${esc(op.kind)} · ${esc(op.id)}</option>`).join('')}`;if(previous&&state.operations.some(op=>op.id===previous))opSelect.value=previous;
  const rows=entries.map(item=>tableRow([
    tableCell(formatDate(item.timestamp),'timestamp',item.timestamp||''),
    tableCell(`${badge(item.level)} ${badge(item.source)}`,'status-cell'),
    tableCell(`<span class="cell-title">${esc(item.eventType)}</span><span class="cell-meta">${esc(item.message)}</span>`),
    tableCell(`<span class="cell-title technical">${esc(item.operationId||item.resourceId||'—')}</span><span class="cell-meta">${esc(item.stepKey||item.resourceType||item.targetRef||'—')}</span>`),
    tableCell(`<span class="technical">${esc(item.actorId||'—')}</span>${item.evidenceDigest?`<span class="cell-meta technical">${esc(shortDigest(item.evidenceDigest))}</span>`:''}`)
  ]));
  $('#log-center-grid').innerHTML=dataTable('Product logs',[{label:'Time',className:'timestamp'},{label:'Level / source'},{label:'Event / message'},{label:'Context'},{label:'Actor / evidence'}],rows,'No product logs','No matching log entry exists in the loaded authorized window.',{key:'product-log-center'});
  const searchState=result.windowTruncated?(result.searchComplete?'window truncated':'search is window-bounded; older matches may exist'):'loaded source windows complete';
  $('#log-center-authority').innerHTML=`<strong>${esc(result.authority||'PRODUCT_LOG_CENTER_V1')}</strong> · ${esc(result.searchSemantics||'LATEST_AUTHORIZED_PRODUCT_LOG_WINDOWS_V1')} · ${esc(searchState)} · payloads ${esc(result.payloadPolicy||'metadata only')} · runtime workload tail ${result.runtimeWorkloadTail?'enabled':'not enabled'}`;
}
async function refreshQueueCenter(){state.queueCenter=await api('/api/v1/operations/queue-center?limit=100');renderOperationsQueueCenter();}
async function refreshProductLogs(){
  const params=new URLSearchParams({limit:'100'}),source=$('#log-center-source')?.value||'',level=$('#log-center-level')?.value||'ALL',operationId=$('#log-center-operation')?.value||'',q=$('#log-center-query')?.value?.trim()||'';
  if(source)params.set('source',source);if(level&&level!=='ALL')params.set('level',level);if(operationId){params.set('operationId',operationId);params.set('source','operation');}if(q)params.set('q',q);
  state.productLogs=await api(`/api/v1/logs?${params.toString()}`);renderProductLogCenter();
}
$('#queue-center-refresh').onclick=async()=>{try{await refreshQueueCenter();toast('Queue Center refreshed.');}catch(error){toast(error.message,'error');}};
$('#log-center-refresh').onclick=async()=>{try{await refreshProductLogs();toast('Product logs refreshed.');}catch(error){toast(error.message,'error');}};
$('#log-center-form').onsubmit=async event=>{event.preventDefault();try{await refreshProductLogs();}catch(error){toast(error.message,'error');}};

function operationClusterRows(){return (state.clusters||[]).map(row=>row.cluster||row).filter(Boolean);}
function renderWorkloadLogSelectors(){
  const project=$('#workload-log-project'),cluster=$('#workload-log-cluster'),workload=$('#workload-log-workload');if(!project||!cluster||!workload)return;
  const projects=(state.projects||[]).filter(item=>projectBelongsToGlobalScope(item.id));setProjectOptions(project,projects,item=>`${item.displayName||item.name||item.id} · ${item.name||item.id}`,'No accessible project');
  const selectedProject=project.value,clusters=operationClusterRows().filter(item=>item.projectId===selectedProject&&item.connectionState!=='REVOKED');setOptions(cluster,clusters,item=>item.id,item=>`${item.displayName||item.name||item.id} · ${item.connectionState||'UNKNOWN'}`,'No connected cluster');
  const explorer=state.workloadLogExplorer;if(!explorer||explorer.clusterId!==cluster.value){workload.innerHTML='<option value="">Load a cluster workload inventory</option>';workload.disabled=true;return;}
  const rows=(explorer.workloads||[]);workload.innerHTML=rows.length?rows.map((item,index)=>`<option value="${index}">${esc(item.kind)} · ${esc(item.namespace)}/${esc(item.name)}</option>`).join(''):'<option value="">No workloads in current inventory</option>';workload.disabled=!rows.length;
}
async function refreshWorkloadLogExplorer(){
  const clusterId=$('#workload-log-cluster')?.value||'';state.workloadLogExplorer=null;renderWorkloadLogSelectors();if(!clusterId)return;
  const explorer=await api(`/api/v1/clusters/${clusterId}/workloads`);state.workloadLogExplorer={...explorer,clusterId};renderWorkloadLogSelectors();
}
function renderWorkloadLogResult(view=state.workloadLogQuery){
  const status=$('#workload-log-status'),grid=$('#workload-log-grid');if(!status||!grid)return;if(!view){status.innerHTML='<span>No target workload log query has been submitted.</span>';grid.innerHTML='';return;}
  const op=view.operation||{},lines=view.lines||[],evidence=view.evidence||{};status.innerHTML=`<strong>${esc(op.kind||'target.logs.query')}</strong> · ${badge(op.state||'UNKNOWN')} · operation <span class="technical">${esc(op.id||'—')}</span> · inventory <span class="technical">${esc(shortDigest(op.desiredRevision||''))}</span>${view.ready?` · sealed evidence <span class="technical">${esc(shortDigest(evidence.digest||''))}</span>`:' · waiting for connected Agent'}`;
  const rows=lines.map(item=>tableRow([tableCell(formatDate(item.timestamp),'timestamp',item.timestamp||''),tableCell(`<span class="technical">${esc(item.pod)}</span><span class="cell-meta">${esc(item.container||'—')}</span>`),tableCell(`<span class="technical log-line">${esc(item.line)}</span>`)]));
  grid.innerHTML=dataTable('Target workload logs',[{label:'Time',className:'timestamp'},{label:'Pod / container'},{label:'Line'}],rows,'No target log lines','The bounded query completed without matching log lines.',{key:'target-workload-logs'});
}
async function pollWorkloadLogQuery(operationId){
  for(let attempt=0;attempt<60;attempt++){
    const view=await api(`/api/v1/workload-log-queries/${operationId}`);state.workloadLogQuery=view;renderWorkloadLogResult(view);
    const terminal=['SUCCEEDED','FAILED','CANCELLED','ROLLED_BACK','NEEDS_OPERATOR'].includes(view.operation?.state);if(view.ready||terminal)return view;
    await new Promise(resolve=>setTimeout(resolve,1500));
  }
  throw new Error('Target workload log query is still running. Keep the Operation ID and refresh Operations to inspect its durable state.');
}
$('#workload-log-project').onchange=()=>{state.workloadLogExplorer=null;renderWorkloadLogSelectors();refreshWorkloadLogExplorer().catch(error=>toast(error.message,'error'));};
$('#workload-log-cluster').onchange=()=>refreshWorkloadLogExplorer().catch(error=>toast(error.message,'error'));
$('#workload-log-form').onsubmit=async event=>{event.preventDefault();const button=event.submitter||$('#workload-log-form button[type="submit"]');try{
  const explorer=state.workloadLogExplorer,index=Number($('#workload-log-workload').value),item=explorer?.workloads?.[index];if(!item)throw new Error('Select a workload from the current authoritative inventory.');
  if(button)button.disabled=true;const body={projectId:$('#workload-log-project').value,clusterId:$('#workload-log-cluster').value,namespace:item.namespace,workloadKind:item.kind,workloadName:item.name,container:$('#workload-log-container').value.trim(),mode:$('#workload-log-mode').value,sinceSeconds:Number($('#workload-log-since').value),limit:Number($('#workload-log-limit').value)};
  const key=`target-logs-${Date.now()}-${globalThis.crypto?.randomUUID?.()||Math.random().toString(36).slice(2)}`;const created=await api('/api/v1/workload-log-queries',{method:'POST',headers:{'Idempotency-Key':key},body});state.workloadLogQuery={operation:created.operation,ready:false};renderWorkloadLogResult();toast('Target workload log query queued.');await pollWorkloadLogQuery(created.operation.id);
}catch(error){toast(error.message,'error');}finally{if(button)button.disabled=false;}};

async function loadOperations(){
  try{
    const securityAllowed=mayAdministerIdentityAuthority();
    const [summary,operations,audit,queueCenter,productLogs,securityAudit,autopilotStatus,supportProfiles,projects,clusters]=await Promise.all([softApi('/api/v1/control-plane/summary',{},'control-plane summary'),softApi('/api/v1/operations?limit=200',[],'operations'),softApi('/api/v1/audit-events?limit=100',[],'audit'),softApi('/api/v1/operations/queue-center?limit=100',{authority:'OPERATIONS_QUEUE_CENTER_V1',lanes:[],items:[]},'queue center'),softApi('/api/v1/logs?limit=100',{authority:'PRODUCT_LOG_CENTER_V1',entries:[]},'product logs'),securityAllowed?softApi('/api/v1/security-audit-events?limit=200',[],'security audit'):Promise.resolve([]),securityAllowed?softApi('/api/v1/autopilot/status',{configured:false,available:false},'autopilot status'):Promise.resolve({configured:false,available:false,message:'Platform-admin role is required.'}),softApi('/api/v1/support-bundles/profiles',[],'support profiles'),softApi('/api/v1/projects',[],'projects'),softApi('/api/v1/clusters',[],'clusters')]);
    Object.assign(state,{summary,operations,audit,queueCenter,productLogs,securityAudit,autopilotStatus,supportProfiles,projects,clusters}); renderAutopilotCampaign(); renderSupportCenter(); renderOperationsQueueCenter(); renderProductLogCenter(); renderWorkloadLogSelectors();
    const operationsLane=queueLane(queueCenter,'operations');
    $('#control-plane-summary').innerHTML=[['Authority',summary.authorityBackend,'authoritative store'],['Operations',summary.operations,`${summary.evidence} evidence records`],['Pending',operationsLane.pending||0,'exact scoped durable-operation states'],['Executing',operationsLane.executing||0,'running / verifying / rollback'],['Needs attention',operationsLane.attention||0,'failed / plan failed / operator required'],['Expired loaded leases',operationsLane.expiredClaims||0,'visible Queue Center window'],['Outbox pending',summary.unpublishedOutbox,'scoped durable events'],['Audit events',summary.auditEvents,'append-only history']].map(([label,value,detail])=>`<article class="metric-card"><strong>${esc(value)}</strong><span>${esc(label)}</span><small>${esc(detail)}</small></article>`).join('');
    const operationRows=latest(operations).map(op=>{
      const flags=[op.retryExhausted?badge('RETRY EXHAUSTED'):'',op.recoveryCheckpointId?badge('RECOVERY BOUND'):'',op.compensationPlanDigest?badge('COMPENSATION BOUND'):'',op.state==='NEEDS_OPERATOR'?badge('OPERATOR REQUIRED'):''].join(' ');
      const managedOKDApproval=op.kind==='managed.okd.install'&&op.state==='AWAITING_APPROVAL'?approvalControl({...op,requestedBy:op.actorId},'Approve OKD install',`data-managed-okd-approval="${esc(op.id)}" data-revision="${esc(op.revision)}"`):'';
      const actions=`<div class="row-actions"><button type="button" class="secondary small-button" data-operation-id="${esc(op.id)}">Inspect</button><button type="button" class="secondary small-button" data-operation-logs="${esc(op.id)}">Logs</button><button type="button" class="secondary small-button" data-operation-bundle="${esc(op.id)}">Bundle</button>${managedOKDApproval}${['FAILED','CANCEL_REQUESTED'].includes(op.state)&&op.compensationPlanDigest&&op.compensationStepCount>0?`<button type="button" class="primary small-button" data-operation-action="recover" data-id="${esc(op.id)}">Start recovery</button>`:''}${!['SUCCEEDED','ROLLED_BACK','CANCELLED','FAILED'].includes(op.state)?`<button type="button" class="danger small-button" data-operation-cancel="${esc(op.id)}">Cancel</button>`:''}</div>`;
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
$('#operation-grid').onclick=async event=>{const managedApproval=event.target.closest('[data-managed-okd-approval]');if(managedApproval){const op=state.operations.find(item=>item.id===managedApproval.dataset.managedOkdApproval);if(!op)return;if(!await confirmAction('Approve managed OKD install',`Approve the sealed Compact-3 install request ${op.targetRef}? The requester cannot approve their own request and execution remains evidence-tracked.`))return;try{await api(`/api/v1/managed-okd-installs/${op.id}/approve`,{method:'POST',headers:{'If-Match':`"${op.revision}"`},body:{}});toast('Managed OKD install approved and queued. Follow progress and evidence here.');await loadOperations();}catch(error){toast(error.message,'error');}return;}const logs=event.target.closest('[data-operation-logs]');if(logs){$('#log-center-operation').value=logs.dataset.operationLogs;$('#log-center-source').value='operation';try{await refreshProductLogs();$('#product-log-center').scrollIntoView({behavior:'smooth',block:'start'});}catch(error){toast(error.message,'error');}return;}const recovery=event.target.closest('[data-operation-action="recover"]');if(recovery){const op=state.operations.find(item=>item.id===recovery.dataset.id);if(!op)return;if(!await confirmAction('Start operation recovery',`Begin the bound compensation plan for ${op.kind}? Completed forward steps will be reversed in safe order and evidence remains attached to the same operation.`,true))return;try{await api(`/api/v1/operations/${op.id}/compensation/start`,{method:'POST',headers:{'If-Match':`"${op.revision}"`},body:{}});toast('Operation recovery accepted. Follow rollback steps and evidence in Operations.');await loadOperations();}catch(error){toast(error.message,'error');}return;}const bundle=event.target.closest('[data-operation-bundle]');if(bundle){try{await downloadSupportBundle({profile:'operation-diagnostics',operationId:bundle.dataset.operationBundle});toast('Operation support bundle downloaded.');}catch(error){toast(error.message,'error');}return;}const cancel=event.target.closest('[data-operation-cancel]');if(cancel){const op=state.operations.find(item=>item.id===cancel.dataset.operationCancel);if(!op)return;if(!await confirmAction('Cancel operation safely',`Request cancellation for ${op.kind}? In-flight work is drained to a safe boundary before final cancellation.`))return;try{await api(`/api/v1/operations/${op.id}/cancel`,{method:'POST',headers:{'If-Match':`"${op.revision}"`},body:{reason:'operator requested safe cancellation from console'}});toast('Cancellation requested.');await loadOperations();}catch(error){toast(error.message,'error');}return;}const button=event.target.closest('[data-operation-id]');if(!button)return;try{const view=await api(`/api/v1/operations/${button.dataset.operationId}`),op=view.operation;showDetails(op.kind,`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(op.id)}</dd><dt>State</dt><dd>${badge(op.state)}</dd><dt>Class</dt><dd>${badge(op.class||'MUTATING')}</dd><dt>Target</dt><dd class="technical">${esc(op.targetRef)}</dd><dt>Risk</dt><dd>${esc(op.risk)}</dd><dt>Attempt</dt><dd>${esc(op.attempt||0)} / ${esc(op.retryPolicy?.maxAttempts||'—')}</dd><dt>Execution authority</dt><dd>Service Account · <span class="technical">operation.execute</span></dd><dt>Lease owner</dt><dd class="technical">${esc(op.leaseOwner||'—')}</dd><dt>Lease expiry</dt><dd>${formatDate(op.leaseExpiresAt)}</dd><dt>Fence</dt><dd class="technical">${esc(op.fenceToken||'—')}</dd><dt>Retry classes</dt><dd>${esc((op.retryPolicy?.retryableClasses||[]).join(', ')||'—')}</dd><dt>Backoff</dt><dd>${esc(op.retryPolicy?.initialBackoffSeconds||'—')}s → max ${esc(op.retryPolicy?.maxBackoffSeconds||'—')}s</dd><dt>Next attempt</dt><dd>${formatDate(op.nextAttemptAt)}</dd><dt>Last failure class</dt><dd>${esc(op.lastFailureClass||'—')}</dd><dt>Recovery checkpoint</dt><dd class="technical">${esc(op.recoveryCheckpointId||'—')}</dd><dt>Recovery evidence</dt><dd class="technical">${esc(op.recoveryEvidenceDigest||'—')}</dd><dt>Compensation plan</dt><dd class="technical">${esc(op.compensationPlanDigest||'—')}</dd><dt>Compensation steps</dt><dd>${esc(op.compensationStepCount||0)} · cursor ${esc(op.compensationCursor||0)}</dd><dt>Compensation failure step</dt><dd class="technical">${esc(op.compensationFailureStep||'—')}</dd><dt>Cancellation</dt><dd>${esc(op.cancelReason||'—')}</dd><dt>Actor</dt><dd>${esc(op.actorId)}</dd><dt>Desired revision</dt><dd class="technical">${esc(op.desiredRevision)}</dd><dt>Error</dt><dd>${esc(op.lastError||'—')}</dd></dl><div class="detail-section"><h3>Steps</h3><div class="timeline">${(view.steps||[]).map(step=>`<div class="timeline-step ${step.state==='SUCCEEDED'?'success':step.state==='FAILED'?'failed':''}"><span class="timeline-dot">${step.state==='SUCCEEDED'?'✓':step.state==='FAILED'?'!':'○'}</span><div><h4>${esc(step.stepKey)}</h4><p>${esc(step.state)} · attempt ${esc(step.attempt)}${step.lastError?` · ${esc(step.lastError)}`:''}</p></div></div>`).join('')||'<p>No operation steps.</p>'}</div></div><div class="detail-section"><h3>Compensation</h3><div class="timeline">${(view.compensation||[]).slice().sort((a,b)=>b.forwardOrder-a.forwardOrder).map(step=>`<div class="timeline-step ${step.state==='SUCCEEDED'?'success':['FAILED','MANUAL_REQUIRED'].includes(step.state)?'failed':''}"><span class="timeline-dot">${step.state==='SUCCEEDED'?'✓':['FAILED','MANUAL_REQUIRED'].includes(step.state)?'!':'↩'}</span><div><h4>${esc(step.stepKey)} · ${esc(step.strategy)}</h4><p>forward #${esc(step.forwardOrder)} · ${step.forwardCompleted?'committed':'not committed'} · compensation ${esc(step.state)} · attempt ${esc(step.attempt)}/${esc(step.maxAttempts)}${step.evidenceDigest?` · ${esc(shortDigest(step.evidenceDigest))}`:''}${step.lastError?` · ${esc(step.lastError)}`:''}</p></div></div>`).join('')||'<p>No compensation plan is bound.</p>'}</div></div><div class="detail-section"><h3>Step trace / logs & evidence</h3><div class="resource-details">${detailRow('Trace authority',view.traceMethod||'—')}${detailRow('Trace entries',(view.traces||[]).length)}${detailRow('Payload evidence',(view.evidence||[]).filter(item=>item.hasPayload).length)}</div><div class="timeline">${(view.traces||[]).map(trace=>`<div class="timeline-step ${trace.level==='ERROR'?'failed':trace.level==='WARN'?'':'success'}"><span class="timeline-dot">${trace.level==='ERROR'?'!':trace.level==='WARN'?'△':'•'}</span><div><h4>${esc(trace.phase)} · ${esc(trace.stepKey)} · attempt ${esc(trace.attempt)} · #${esc(trace.sequence)}</h4><p>${badge(trace.level)} ${esc(trace.eventType)} · ${esc(trace.message)}</p><small class="technical">trace ${esc(trace.traceKey)} · evidence ${esc(trace.evidenceId||'—')} · ${esc(shortDigest(trace.evidenceDigest||''))}</small></div></div>`).join('')||'<p>No per-step trace has been sealed.</p>'}</div></div><div class="detail-section"><h3>Evidence</h3>${(view.evidence||[]).length?`<dl class="key-value">${view.evidence.map(item=>`<dt>${esc(item.kind)}</dt><dd><span class="technical">${esc(item.digest)}</span><br>${esc(item.phase||'OPERATION')} · ${esc(item.stepKey||'operation')} · attempt ${esc(item.attempt||0)} · ${esc(item.location)} · ${item.sealed?'sealed':'unsealed'} · payload ${item.hasPayload?'available':'metadata-only'}${item.traceId?` · trace ${esc(item.traceId)}`:''}${item.hasPayload?`<br><button type="button" class="secondary small-button" data-operation-id="${esc(op.id)}" data-operation-evidence-payload="${esc(item.id)}">Inspect payload</button>`:''}</dd>`).join('')}</dl>`:'<p>No evidence attached.</p>'}</div>`);}catch(error){toast(error.message,'error');}};


function notificationOrgProjects(orgId){ return state.projects.filter(project=>project.organizationId===orgId); }
function renderNotificationEventTypes(){
  const selected=new Set($$('#notification-event-type-list input:checked').map(input=>input.value));
  $('#notification-event-type-list').innerHTML=state.notificationEventTypes.length?state.notificationEventTypes.map(item=>`<label class="activity-item"><span class="activity-main"><input type="checkbox" data-notification-event-type value="${esc(item.eventType)}"${selected.has(item.eventType)?' checked':''}><span><strong class="technical">${esc(item.eventType)}</strong><small>${esc(item.description)} · ${esc(item.severity)}</small></span></span></label>`).join(''):emptyState('No event types','The notification event contract is unavailable.');
}
function renderNotificationSelectors(){
  const orgDest=$('#notification-destination-organization'),orgRoute=$('#notification-route-organization'),orgPreview=$('#notification-preview-organization');
  const previousPreviewOrg=orgPreview?.value||'';
  setOptions(orgDest,state.organizations,item=>item.id,item=>item.displayName||item.name,'Create an organization first');
  setOptions(orgRoute,state.organizations,item=>item.id,item=>item.displayName||item.name,'Create an organization first');
  if(orgPreview){setOptions(orgPreview,state.organizations,item=>item.id,item=>item.displayName||item.name,'Create an organization first');if(previousPreviewOrg&&[...orgPreview.options].some(option=>option.value===previousPreviewOrg))orgPreview.value=previousPreviewOrg;}
  const orgId=orgRoute.value;
  const projects=notificationOrgProjects(orgId),project=$('#notification-route-project'),previousProject=project.value;
  project.innerHTML=`<option value="">All projects in organization</option>`+projects.map(item=>`<option value="${esc(item.id)}">${esc(item.displayName||item.name)}</option>`).join('');
  if([...project.options].some(option=>option.value===previousProject))project.value=previousProject;
  if(orgPreview){const previewProject=$('#notification-preview-project'),previousPreviewProject=previewProject.value,previewProjects=notificationOrgProjects(orgPreview.value);previewProject.innerHTML=`<option value="">Organization-wide event</option>`+previewProjects.map(item=>`<option value="${esc(item.id)}">${esc(item.displayName||item.name)}</option>`).join('');if([...previewProject.options].some(option=>option.value===previousPreviewProject))previewProject.value=previousPreviewProject;const eventSelect=$('#notification-preview-event-type'),previousEvent=eventSelect.value;eventSelect.innerHTML=state.notificationEventTypes.length?state.notificationEventTypes.map(item=>`<option value="${esc(item.eventType)}">${esc(item.eventType)} · ${esc(item.severity)}</option>`).join(''):'<option value="" disabled>No event types available</option>';if(previousEvent&&[...eventSelect.options].some(option=>option.value===previousEvent))eventSelect.value=previousEvent;}
  const active=state.notificationDestinations.filter(item=>item.organizationId===orgId&&item.state==='ACTIVE');
  const destinationSelect=$('#notification-route-destinations'),selected=new Set([...destinationSelect.selectedOptions].map(option=>option.value));
  destinationSelect.innerHTML=active.length?active.map(item=>`<option value="${esc(item.id)}"${selected.has(item.id)?' selected':''}>${esc(item.name)} · ${esc(item.kind)}</option>`).join(''):'<option value="" disabled>No active destinations</option>';
  destinationSelect.disabled=!active.length;
  renderNotificationEventTypes();
}
function renderNotificationRoutingPreview(){
  const target=$('#notification-preview-result');if(!target)return;const preview=state.notificationRoutingPreview;if(!preview){target.innerHTML='<p class="muted">Choose event scope, type and severity to inspect matching rules and destinations.</p>';return;}
  const routes=preview.matchedRoutes||[];const summary=`<div class="metric-grid"><div class="metric"><span>Matched rules</span><strong>${esc(preview.routeCount||0)}</strong></div><div class="metric"><span>Active destinations</span><strong>${esc(preview.destinationCount||0)}</strong></div><div class="metric"><span>Side effects</span><strong>${preview.sideEffects?'YES':'NONE'}</strong></div></div>`;
  const rows=routes.map(route=>`<article class="activity-item"><div class="activity-main"><span class="status-dot ${route.destinations?.length?'ok':'warn'}"></span><div><strong>${esc(route.name)}</strong><p>${route.projectId?`Project ${technical(route.projectId)}`:'Organization-wide'} · minimum ${badge(route.minimumSeverity)} · ${esc((route.eventPatterns||[]).join(', '))}</p><small>${(route.destinations||[]).length?(route.destinations||[]).map(destination=>`${esc(destination.name)} · ${esc(destination.kind)} · ${esc(destination.state)}`).join(' · '):'No active destination remains for this matched rule.'}</small></div></div></article>`).join('');
  target.innerHTML=`${summary}<div class="inline-summary"><strong class="technical">${esc(preview.eventType)}</strong> ${badge(preview.severity)} · ${preview.projectId?`project ${technical(preview.projectId)}`:'organization-wide'} · authority ${technical(preview.authority||'—')}</div>${rows||emptyState('No matching routes','This event would create no notification deliveries under the current routing authority.')}<p class="status-note">Preview is side-effect free. Delivery created: ${preview.deliveryCreated?'yes':'no'}.</p>`;
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
  const providerGrid=$('#notification-provider-contract-grid');if(providerGrid)providerGrid.innerHTML=state.notificationProviderContracts.length?state.notificationProviderContracts.map(item=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.kind)}</h3><div class="resource-meta">${badge(item.transport)}${badge(item.externalEgress?'EXTERNAL EGRESS':'LOCAL')}</div></div></div><div class="resource-details">${detailRow('Authorization',item.supportsAuthorization?'supported':'not used')}${detailRow('HMAC',item.supportsHmac?'supported':'not used')}${detailRow('Durable delivery',item.deliveryDurable?'yes':'no')}${detailRow('Retry / dead letter',item.retryAndDeadLetter?'yes':'no')}${detailRow('Raw secret material',item.rawSecretMaterialAllowed?'ALLOWED':'forbidden')}</div></article>`).join(''):emptyState('Provider contracts unavailable','Notification adapter authority was not returned by the API.');
  const destinationRows=latest(state.notificationDestinations).map(item=>tableRow([
    tableCell(`<span class="cell-title">${esc(item.name)}</span><span class="cell-meta">${esc(orgById.get(item.organizationId)?.displayName||item.organizationId)}</span>`),
    tableCell(`${badge(item.kind)} ${badge(item.state)}`,'status-cell'),
    tableCell(`<span class="technical">${esc(item.endpoint||'Local console')}</span>`),
    tableCell(`${esc(item.timeoutSeconds||10)}s`,'numeric'),
    tableCell(`<div class="row-actions"><button type="button" class="secondary small-button" data-notification-destination-action="inspect" data-id="${esc(item.id)}">Inspect</button>${item.state==='ACTIVE'?`<button type="button" class="secondary small-button" data-notification-destination-action="edit" data-id="${esc(item.id)}">Edit</button><button type="button" class="danger small-button" data-notification-destination-action="disable" data-id="${esc(item.id)}">Disable</button>`:''}</div>`,'actions-cell')
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
    const [organizations,projects,eventTypes,providerContracts,destinations,routes,events,deliveries]=await Promise.all([softApi('/api/v1/organizations',[],'organizations'),softApi('/api/v1/projects',[],'projects'),softApi('/api/v1/notification-event-types',[],'notification event types'),softApi('/api/v1/notification-provider-contracts',[],'notification provider contracts'),softApi('/api/v1/notification-destinations',[],'notification destinations'),softApi('/api/v1/notification-routes',[],'notification routes'),softApi('/api/v1/notification-events?limit=100',[],'notification events'),softApi('/api/v1/notification-deliveries?limit=100',[],'notification deliveries')]);
    Object.assign(state,{organizations,projects,notificationEventTypes:eventTypes,notificationProviderContracts:providerContracts,notificationDestinations:destinations,notificationRoutes:routes,notificationEvents:events,notificationDeliveries:deliveries});
    renderNotificationSelectors();renderNotificationResources();renderNotificationRoutingPreview();
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
$('#notification-preview-organization').onchange=()=>{state.notificationRoutingPreview=null;renderNotificationSelectors();renderNotificationRoutingPreview();};
$('#notification-destination-cancel-edit').onclick=async()=>{const form=$('#notification-destination-form');if(!await confirmDiscardDirty(form,'Discard destination changes?','Cancel editing and discard unsaved notification destination changes?'))return;resetNotificationDestinationForm();};
$('#notification-route-cancel-edit').onclick=async()=>{const form=$('#notification-route-form');if(!await confirmDiscardDirty(form,'Discard routing changes?','Cancel editing and discard unsaved notification routing changes?'))return;resetNotificationRouteForm();};
$('#notification-destination-form').onsubmit=async event=>{
  event.preventDefault();const form=event.currentTarget;if(!form.reportValidity())return;const kind=$('#notification-destination-kind').value;const editing=form.dataset.editId;
  const body={organizationId:editing?(state.notificationDestinations.find(item=>item.id===editing)?.organizationId||$('#notification-destination-organization').value):$('#notification-destination-organization').value,name:$('#notification-destination-name').value.trim(),kind,endpoint:kind==='WEBHOOK'?$('#notification-destination-endpoint').value.trim():'',authorizationEnv:kind==='WEBHOOK'?$('#notification-destination-auth-env').value.trim():'',hmacSecretEnv:kind==='WEBHOOK'?$('#notification-destination-hmac-env').value.trim():'',allowHttp:kind==='WEBHOOK'&&$('#notification-destination-allow-http').checked,timeoutSeconds:Number($('#notification-destination-timeout').value||10)};
  try{if(editing)await api(`/api/v1/notification-destinations/${editing}`,{method:'PUT',headers:{'If-Match':`"${form.dataset.revision}"`},body});else await api('/api/v1/notification-destinations',{method:'POST',body});toast(editing?'Notification destination updated.':'Notification destination created.');resetNotificationDestinationForm();await loadNotifications();}catch(error){toast(error.message,'error');}
};
$('#notification-preview-form').onsubmit=async event=>{
  event.preventDefault();const form=event.currentTarget;if(!form.reportValidity())return;const body={organizationId:$('#notification-preview-organization').value,projectId:$('#notification-preview-project').value||'',eventType:$('#notification-preview-event-type').value,severity:$('#notification-preview-severity').value};
  try{state.notificationRoutingPreview=await api('/api/v1/notification-routing/preview',{method:'POST',body});renderNotificationRoutingPreview();toast('Notification routing preview refreshed.');}catch(error){state.notificationRoutingPreview=null;$('#notification-preview-result').innerHTML=errorState(error.message);toast(error.message,'error');}
};
$('#notification-route-form').onsubmit=async event=>{
  event.preventDefault();const form=event.currentTarget;if(!form.reportValidity())return;const eventPatterns=$$('#notification-event-type-list input:checked').map(input=>input.value),destinationIds=[...$('#notification-route-destinations').selectedOptions].map(option=>option.value).filter(Boolean);if(!eventPatterns.length){toast('Select at least one event type.','error');return;}if(!destinationIds.length){toast('Select at least one active destination.','error');return;}const editing=form.dataset.editId;
  const body={organizationId:editing?(state.notificationRoutes.find(item=>item.id===editing)?.organizationId||$('#notification-route-organization').value):$('#notification-route-organization').value,projectId:$('#notification-route-project').value||'',name:$('#notification-route-name').value.trim(),enabled:editing?form.dataset.enabled==='true':true,eventPatterns,minimumSeverity:$('#notification-route-severity').value,destinationIds};
  try{if(editing)await api(`/api/v1/notification-routes/${editing}`,{method:'PUT',headers:{'If-Match':`"${form.dataset.revision}"`},body});else await api('/api/v1/notification-routes',{method:'POST',body});toast(editing?'Notification routing rule updated.':'Notification routing rule created.');resetNotificationRouteForm();await loadNotifications();}catch(error){toast(error.message,'error');}
};
$('#notification-destination-grid').onclick=async event=>{const button=event.target.closest('[data-notification-destination-action]');if(!button)return;const item=state.notificationDestinations.find(v=>v.id===button.dataset.id);if(!item)return;if(button.dataset.notificationDestinationAction==='inspect'){showDetails('Notification destination',`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(item.id)}</dd><dt>Kind / state</dt><dd>${badge(item.kind)} ${badge(item.state)}</dd><dt>Endpoint</dt><dd class="technical">${esc(item.endpoint||'Local console')}</dd><dt>Authorization env</dt><dd class="technical">${esc(item.authorizationEnv||'—')}</dd><dt>HMAC env</dt><dd class="technical">${esc(item.hmacSecretEnv||'—')}</dd><dt>Allow HTTP</dt><dd>${item.allowHttp?'yes':'no'}</dd><dt>Revision</dt><dd>${esc(item.revision)}</dd></dl>`);return;}if(button.dataset.notificationDestinationAction==='edit'){const form=$('#notification-destination-form');if(form.dataset.editId===item.id&&dirtyWithin(form)){form.scrollIntoView({behavior:'smooth',block:'center'});return;}if(!await confirmDiscardDirty(form,'Replace unsaved destination changes?','Open this destination and discard the unsaved values currently in the destination editor?'))return;editNotificationDestination(item);return;}if(button.dataset.notificationDestinationAction==='disable'){if(!await confirmAction('Disable notification destination','Disable this destination? Existing history remains, but new matching deliveries will no longer target it.',true))return;try{await api(`/api/v1/notification-destinations/${item.id}/disable`,{method:'POST',headers:{'If-Match':`"${item.revision}"`,'X-Confirm-Disable':'disable-notification-destination'},body:{}});toast('Notification destination disabled.');await loadNotifications();}catch(error){toast(error.message,'error');}}};
$('#notification-route-grid').onclick=async event=>{const button=event.target.closest('[data-notification-route-action]');if(!button)return;const item=state.notificationRoutes.find(v=>v.id===button.dataset.id);if(!item)return;if(button.dataset.notificationRouteAction==='inspect'){let policy=null;try{policy=await api(`/api/v1/notification-routes/${item.id}/policy-digest`);}catch(_error){}showDetails('Notification route',`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(item.id)}</dd><dt>Enabled</dt><dd>${esc(item.enabled)}</dd><dt>Minimum severity</dt><dd>${badge(item.minimumSeverity)}</dd><dt>Event patterns</dt><dd class="technical">${esc((item.eventPatterns||[]).join(', '))}</dd><dt>Destinations</dt><dd class="technical">${esc((item.destinationIds||[]).join(', '))}</dd><dt>Policy digest</dt><dd class="technical">${esc(policy?.digest||'Unavailable')}</dd><dt>Revision</dt><dd>${esc(item.revision)}</dd></dl>`);return;}if(button.dataset.notificationRouteAction==='edit'){const form=$('#notification-route-form');if(form.dataset.editId===item.id&&dirtyWithin(form)){form.scrollIntoView({behavior:'smooth',block:'center'});return;}if(!await confirmDiscardDirty(form,'Replace unsaved routing changes?','Open this routing rule and discard the unsaved values currently in the routing editor?'))return;editNotificationRoute(item);return;}if(button.dataset.notificationRouteAction==='toggle'){const enabling=!item.enabled;const title=enabling?'Enable notification route':'Disable notification route';const impact=enabling?'Enable this route? New matching events will begin creating deliveries to its configured destinations.':'Disable this route? Existing history remains, but new matching events will stop creating deliveries for this rule.';if(!await confirmAction(title,impact,!enabling))return;try{await api(`/api/v1/notification-routes/${item.id}`,{method:'PUT',headers:{'If-Match':`"${item.revision}"`},body:{organizationId:item.organizationId,projectId:item.projectId||'',name:item.name,enabled:enabling,eventPatterns:item.eventPatterns,minimumSeverity:item.minimumSeverity,destinationIds:item.destinationIds}});toast(enabling?'Routing rule enabled.':'Routing rule disabled.');await loadNotifications();}catch(error){toast(error.message,'error');}}};
$('#notification-event-grid').onclick=event=>{const button=event.target.closest('[data-notification-event-id]');if(!button)return;const item=state.notificationEvents.find(v=>v.id===button.dataset.notificationEventId);if(!item)return;showDetails(item.title||item.eventType,`<dl class="key-value"><dt>Event type</dt><dd class="technical">${esc(item.eventType)}</dd><dt>Severity</dt><dd>${badge(item.severity)}</dd><dt>Source event</dt><dd class="technical">${esc(item.sourceEventId)}</dd><dt>Aggregate</dt><dd class="technical">${esc(item.aggregateType)} / ${esc(item.aggregateId)}</dd><dt>Occurred</dt><dd>${formatDate(item.occurredAt)}</dd><dt>Summary</dt><dd>${esc(item.summary||'—')}</dd></dl>`);};
$('#notification-delivery-grid').onclick=async event=>{const button=event.target.closest('[data-notification-delivery-id]');if(!button)return;try{const view=await api(`/api/v1/notification-deliveries/${button.dataset.notificationDeliveryId}`),item=view.delivery,sourceEvent=view.event||state.notificationEvents.find(v=>v.id===item.eventId)||null,attempts=view.attempts||[];const retryScope=sourceEvent?.projectId?` data-project-scope="${esc(sourceEvent.projectId)}"`:sourceEvent?.organizationId?` data-organization-scope="${esc(sourceEvent.organizationId)}"`:' data-project-scope="__permission-scope-unavailable__"';const retry=item.state==='DEAD_LETTER'?`<div class="detail-section"><button type="button" data-notification-retry-dead-letter="${esc(item.id)}"${retryScope} class="primary">Requeue dead letter</button></div>`:'';showDetails('Notification delivery',`<dl class="key-value"><dt>ID</dt><dd class="technical">${esc(item.id)}</dd><dt>State</dt><dd>${badge(item.state)}</dd><dt>Attempt</dt><dd>${esc(item.attempt)} / ${esc(item.maxAttempts)}</dd><dt>Last HTTP status</dt><dd>${esc(item.lastStatusCode||'—')}</dd><dt>Last error</dt><dd>${esc(item.lastError||'—')}</dd><dt>Next attempt</dt><dd>${formatDate(item.nextAttemptAt)}</dd></dl><div class="detail-section"><h3>Immutable attempts</h3><div class="timeline">${attempts.length?attempts.map(attempt=>`<div class="timeline-step ${attempt.success?'success':attempt.retryable?'':'failed'}"><span class="timeline-dot">${attempt.success?'✓':'!'}</span><div><h4>Attempt ${esc(attempt.attempt)}</h4><p>${attempt.success?'SUCCEEDED':attempt.retryable?'RETRYABLE':'FAILED'} · HTTP ${esc(attempt.statusCode||'—')} · ${esc(attempt.durationMillis||0)} ms${attempt.error?` · ${esc(attempt.error)}`:''}</p><small class="technical">${esc(attempt.responseDigest||'—')}</small></div></div>`).join(''):'<p>No attempts recorded.</p>'}</div></div>${retry}`);if(item.state==='DEAD_LETTER')setTimeout(()=>{const retryButton=document.querySelector('[data-notification-retry-dead-letter]');if(retryButton)retryButton.onclick=async()=>{if(!await confirmAction('Requeue dead letter','Retry this durable delivery after the destination problem has been corrected?'))return;try{await api(`/api/v1/notification-deliveries/${item.id}/retry`,{method:'POST',headers:{'If-Match':`"${item.revision}"`},body:{}});$('#detail-dialog').close();toast('Dead letter requeued.');await loadNotifications();}catch(error){toast(error.message,'error');}};},0);}catch(error){toast(error.message,'error');}};

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
$('#git-provider-grid').onclick=async event=>{const button=event.target.closest('[data-git-provider-action]');if(!button)return;const item=state.gitProviders.find(row=>row.id===button.dataset.id);if(!item)return;if(button.dataset.gitProviderAction==='rebind'){const select=$(`[data-git-provider-credential="${item.id}"]`);const credentialId=select?.value,credential=state.gitCredentials.find(row=>row.id===credentialId);if(!credentialId||credentialId===item.credentialId){toast(credentialId?'Provider already uses this credential.':'Select an active credential.','error');return;}if(!credential||credential.state!=='ACTIVE'){toast('Selected Git credential is no longer ACTIVE. Refresh and select an active credential.','error');return;}if(!await confirmAction('Rebind Git provider credential',`Rebind ${item.name} to credential ${credential.name}? Subsequent Git reads and writes will use the new secret reference.`,false))return;try{await api(`/api/v1/git-providers/${item.id}/credential`,{method:'PUT',headers:{'If-Match':`"${item.revision}"`},body:{credentialId}});toast('Git provider credential binding updated.');await loadServices();}catch(error){toast(error.message,'error');}}};


const externalRegistryAdmissionForm=$('#external-registry-admission-form');
if(externalRegistryAdmissionForm)externalRegistryAdmissionForm.onsubmit=async event=>{event.preventDefault();const form=event.currentTarget;if(!form.reportValidity())return;const projectId=state.globalScope.projectId||'',project=projectId?scopeDirectoryProject(projectId):null,organizationId=state.globalScope.organizationId||project?.organizationId||'';if(!organizationId&&!projectId){toast('Select an organization or project in the global scope first.','error');return;}const body={organizationId,projectId,registryUrl:$('#external-registry-url').value.trim(),imageReference:$('#external-registry-reference').value.trim(),direction:$('#external-registry-direction').value,credentialRef:$('#external-registry-credential-ref').value.trim()};try{const result=await api('/api/v1/external-registry/admission',{method:'POST',body});state.externalRegistryAdmission=result;$('#external-registry-admission-result').innerHTML=`<div class="resource-details">${detailRow('Authority',result.authority,true)}${detailRow('Decision',result.admitted?'ADMITTED':'BLOCKED')}${detailRow('Registry',result.registryHost,true)}${detailRow('Repository',result.repository,true)}${detailRow('Digest',result.digest,true)}${detailRow('Direction',result.direction)}${detailRow('Managed registry authority',result.managedRegistrySoT)}${detailRow('Mutable tags',result.mutableTagsAllowed?'allowed':'forbidden')}${detailRow('Raw credentials',result.rawCredentialsAllowed?'allowed':'forbidden')}</div>`;toast('External registry reference admitted for planning.');}catch(error){state.externalRegistryAdmission=null;$('#external-registry-admission-result').innerHTML=errorState(error.message);toast(error.message,'error');}};

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
$('#git-pull-request-grid').onclick=async event=>{const button=event.target.closest('[data-git-pr-action]');if(!button)return;const action=button.dataset.gitPrAction,id=button.dataset.prId,revision=button.dataset.revision;if(action==='approve'&&!await confirmAction('Approve signed pull request','Approve this exact signed candidate for merge? Approval does not merge or reconcile the desired state.',false))return;if(action==='merge'&&!await confirmAction('Merge signed pull request','Merge this approved signed revision into the managed desired-state branch?',true))return;try{await api(`/api/v1/system-services/git/pull-requests/${id}/${action}`,{method:'POST',headers:{'If-Match':`"${revision}"`},body:{}});toast(action==='approve'?'Pull request approved; merge remains a separate action.':'Pull request merged and recorded as managed desired state.');await loadGitDeliveryAuthority();}catch(error){toast(error.message,'error');}};
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
  setProjectOptions($('#blueprint-overlay-project'),state.projects,item=>item.displayName||item.name);
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
  setProjectOptions(project,state.projects);
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
  $('#blueprint-editor-state').className='badge neutral'; $('#blueprint-editor-state').textContent='NEW DRAFT'; $('#blueprint-release-save').textContent=state.locale==='fa'?'ایجاد پیش‌نویس':'Create draft release';
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

function platformTemplateProjectOptions(){
  for(const id of ['template-schema-project','template-policy-project','platform-template-project'])setProjectOptions($(`#${id}`),state.projects,item=>item.displayName||item.name,'Select project');
}
function renderPlatformTemplateOptions(){
  platformTemplateProjectOptions();
  const projectID=$('#platform-template-project')?.value||'';
  const blueprints=state.blueprintReleases.filter(item=>item.projectId===projectID&&item.state==='PUBLISHED'&&item.executionReady===true);
  const schemas=state.variableSchemas.filter(item=>item.projectId===projectID);
  const policies=state.platformPolicySets.filter(item=>item.projectId===projectID);
  setOptions($('#platform-template-blueprint'),blueprints,item=>item.id,item=>`${item.blueprintName} ${item.blueprintVersion}`,'No eligible Blueprint');
  setOptions($('#platform-template-schema'),schemas,item=>item.id,item=>`${item.name} ${item.version}`,'No variable schema');
  setOptions($('#platform-template-policy'),policies,item=>item.id,item=>`${item.name} ${item.version}`,'No policy set');
}
function renderPlatformTemplateAuthorities(){
  const projectById=new Map(state.projects.map(item=>[item.id,item]));
  $('#template-schema-grid').innerHTML=state.variableSchemas.length?state.variableSchemas.map(item=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.name)} <span class="technical">${esc(item.version)}</span></h3><div class="resource-meta">${badge('VARIABLE SCHEMA')}</div></div></div><p>${esc(projectById.get(item.projectId)?.displayName||item.projectId)}</p><div class="resource-details">${detailRow('Variables',(item.variables||[]).length)}${detailRow('Digest',shortDigest(item.digest))}</div></article>`).join(''):emptyState('No variable schemas','Create a typed schema before composing a platform template.');
  $('#template-policy-grid').innerHTML=state.platformPolicySets.length?state.platformPolicySets.map(item=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.name)} <span class="technical">${esc(item.version)}</span></h3><div class="resource-meta">${badge(item.maintenance?.riskClass||'POLICY')}</div></div></div><p>${esc(projectById.get(item.projectId)?.displayName||item.projectId)}</p><div class="resource-details">${detailRow('Max unavailable',`${item.maintenance?.maxUnavailable||0}%`)}${detailRow('Pod security',item.security?.podSecurityLevel||'—')}${detailRow('Digest',shortDigest(item.digest))}</div></article>`).join(''):emptyState('No policy sets','Create reusable operating policy before composing a platform template.');
  $('#platform-template-grid').innerHTML=state.platformTemplates.length?state.platformTemplates.map(item=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.name)} <span class="technical">${esc(item.version)}</span></h3><div class="resource-meta">${badge(item.impact?.status||'TARGET_PREVIEW_REQUIRED')}</div></div></div><p>${esc(projectById.get(item.projectId)?.displayName||item.projectId)}</p><div class="resource-details">${detailRow('Template digest',shortDigest(item.digest))}${detailRow('Blueprint',shortDigest(item.blueprintDigest))}${detailRow('Variable schema',shortDigest(item.variableSchemaDigest))}${detailRow('Policy set',shortDigest(item.policySetDigest))}${detailRow('Target classes',(item.allowedTargetClasses||[]).join(', ')||'—')}${detailRow('Certification',(item.certificationRequirements||[]).join(', '))}</div><div class="resource-actions"><button class="secondary small-button" type="button" data-template-admission="${esc(item.id)}" data-target-class="${esc((item.allowedTargetClasses||[])[0]||'')}">Check source admission</button></div></article>`).join(''):emptyState('No platform templates','Compose a published Blueprint release, VariableSchema and PolicySet.');
  renderPlatformTemplateOptions();
  renderApplicationPlatformComposition();
}
function applicationProjectName(id){return state.projects.find(item=>item.id===id)?.displayName||id||'—';}
function applicationListOptions(select,items,label){if(!select)return;select.innerHTML='<option value="">Select</option>'+items.map(item=>`<option value="${esc(item.id)}">${esc(label(item))}</option>`).join('');}
function renderApplicationPlatformComposition(){
  const workloadGrid=$('#application-workload-grid'),resourceGrid=$('#application-resource-grid'),releaseGrid=$('#application-release-grid'),bindingGrid=$('#application-binding-grid');
  if(!workloadGrid||!resourceGrid||!releaseGrid||!bindingGrid)return;
  $('#application-workload-count').textContent=state.applicationWorkloadTypes.length;
  $('#application-trait-count').textContent=state.applicationCapabilityTraits.length;
  $('#application-resource-count').textContent=state.applicationResourceTypes.length;
  $('#application-binding-count').textContent=state.applicationEnvironmentBindings.length;
  const traitsByProject=new Map();
  state.applicationCapabilityTraits.forEach(item=>{const rows=traitsByProject.get(item.projectId)||[];rows.push(item);traitsByProject.set(item.projectId,rows);});
  workloadGrid.innerHTML=state.applicationWorkloadTypes.length?state.applicationWorkloadTypes.map(item=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.name)} <span class="technical">${esc(item.version)}</span></h3><div class="resource-meta">${badge('WORKLOAD SHAPE')}</div></div></div><p>${esc(applicationProjectName(item.projectId))}</p><div class="resource-details">${detailRow('Allowed traits',(item.allowedTraitKinds||[]).join(', ')||'None')}${detailRow('Schema',shortDigest(item.inputSchemaDigest))}${detailRow('Digest',shortDigest(item.digest))}</div><div class="resource-actions"><button class="secondary small-button" type="button" data-application-inspect="workload" data-id="${esc(item.id)}">Inspect composition inputs</button></div></article>`).join(''):emptyState('No workload shapes','Create WorkloadType authority through Product API or MCP, then compose it here.');
  const traitCards=state.applicationCapabilityTraits.map(item=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.name)} <span class="technical">${esc(item.version)}</span></h3><div class="resource-meta">${badge(item.kind||'TRAIT')}</div></div></div><p>${esc(applicationProjectName(item.projectId))}</p><div class="resource-details">${detailRow('Capability',item.capability,true)}${detailRow('Native suppression',item.nativeSuppression?'Allowed':'Blocked')}${detailRow('Digest',shortDigest(item.digest))}</div></article>`).join('');
  if(traitCards)workloadGrid.insertAdjacentHTML('beforeend',traitCards);
  resourceGrid.innerHTML=state.applicationResourceTypes.length?state.applicationResourceTypes.map(item=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.name)} <span class="technical">${esc(item.version)}</span></h3><div class="resource-meta">${badge(item.category||'RESOURCE')}</div></div></div><p>${esc(applicationProjectName(item.projectId))}</p><div class="resource-details">${detailRow('Provisioner',item.provisioner)}${detailRow('Delete policy',item.deletePolicy)}${detailRow('Outputs',(item.outputs||[]).map(v=>v.sensitive?`${v.name} → secret reference`:v.name).join(', ')||'—')}${detailRow('Readiness',(item.readinessConditions||[]).join(', ')||'—')}${detailRow('Digest',shortDigest(item.digest))}</div></article>`).join(''):emptyState('No managed dependencies','ManagedResourceType keeps DB/cache/queue/object-store intent behind product-owned authority.');
  const profiles=state.applicationWorkspaceProfiles.map(item=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.name)} <span class="technical">${esc(item.version)}</span></h3><div class="resource-meta">${badge('WORKSPACE PROFILE')}</div></div></div><p>${esc(applicationProjectName(item.projectId))}</p><div class="resource-details">${detailRow('Bound policies',(item.authorityRefs||[]).length)}${detailRow('Digest',shortDigest(item.digest))}</div></article>`).join('');
  const releases=state.applicationReleases.map(item=>`<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.name)} <span class="technical">${esc(item.version)}</span></h3><div class="resource-meta">${badge('IMMUTABLE RELEASE')}</div></div></div><p>${esc(applicationProjectName(item.projectId))}</p><div class="resource-details">${detailRow('Workload',shortDigest(item.workloadTypeDigest))}${detailRow('Traits',(item.traitDigests||[]).length)}${detailRow('Managed dependencies',(item.managedResourceDigests||[]).length)}${detailRow('Source',shortDigest(item.sourceDigest))}${detailRow('Release digest',shortDigest(item.digest))}</div><div class="resource-actions"><button class="secondary small-button" type="button" data-application-inspect="release" data-id="${esc(item.id)}">Inspect immutable release</button></div></article>`).join('');
  releaseGrid.innerHTML=(profiles+releases)||emptyState('No profiles or releases','Bind existing policy authorities into a WorkspaceProfile, then create immutable application releases.');
  bindingGrid.innerHTML=state.applicationEnvironmentBindings.length?state.applicationEnvironmentBindings.map(item=>{const release=state.applicationReleases.find(row=>row.id===item.releaseId);return `<article class="resource-card"><div class="resource-header"><div><h3>${esc(item.environment)} <span class="technical">r${esc(item.revision)}</span></h3><div class="resource-meta">${badge('BOUND')}</div></div></div><p>${esc(applicationProjectName(item.projectId))}</p><div class="resource-details">${detailRow('Release',release?`${release.name} ${release.version}`:item.releaseId,true)}${detailRow('Workspace binding',item.workspaceBindingId,true)}${detailRow('Binding revision',item.workspaceBindingRevision)}${detailRow('Cluster',item.clusterId,true)}${detailRow('Namespace',item.namespace,true)}${detailRow('Capability resolution',shortDigest(item.capabilityResolutionDigest))}${detailRow('Desired binding',shortDigest(item.digest))}</div><div class="resource-actions"><button class="secondary small-button" type="button" data-application-inspect="binding" data-id="${esc(item.id)}">Inspect authority fence</button></div></article>`}).join(''):emptyState('No environment bindings','Bind an immutable release to one active Workspace namespace reference before promotion.');
  applicationListOptions($('#application-resolution-workload'),state.applicationWorkloadTypes,item=>`${item.name} · ${item.version} · ${applicationProjectName(item.projectId)}`);
  const resolveWorkload=state.applicationWorkloadTypes.find(item=>item.id===$('#application-resolution-workload')?.value)||state.applicationWorkloadTypes[0];
  const eligibleTraits=resolveWorkload?(traitsByProject.get(resolveWorkload.projectId)||[]):state.applicationCapabilityTraits;
  const traitSelect=$('#application-resolution-traits');if(traitSelect)traitSelect.innerHTML=eligibleTraits.map(item=>`<option value="${esc(item.id)}">${esc(item.name)} · ${esc(item.capability)}</option>`).join('');
  applicationListOptions($('#application-promotion-binding'),state.applicationEnvironmentBindings,item=>`${item.environment} · ${item.namespace} · r${item.revision}`);
  const selectedBinding=state.applicationEnvironmentBindings.find(item=>item.id===$('#application-promotion-binding')?.value)||state.applicationEnvironmentBindings[0];
  applicationListOptions($('#application-promotion-release'),state.applicationReleases.filter(item=>!selectedBinding||item.projectId===selectedBinding.projectId),item=>`${item.name} · ${item.version}`);
}
async function loadPlatformTemplates(){
  try{
    const [projects,releases,schemas,policies,templates,applicationWorkloadTypes,applicationCapabilityTraits,applicationResourceTypes,applicationWorkspaceProfiles,applicationReleases,applicationEnvironmentBindings]=await Promise.all([softApi('/api/v1/projects',[],'projects'),softApi('/api/v1/blueprint-releases',[],'blueprint releases'),softApi('/api/v1/variable-schemas',[],'variable schemas'),softApi('/api/v1/platform-policy-sets',[],'platform policy sets'),softApi('/api/v1/platform-templates',[],'platform templates'),softApi('/api/v1/application-platform/workload-types',[],'application workload shapes'),softApi('/api/v1/application-platform/capability-traits',[],'application capability traits'),softApi('/api/v1/application-platform/resource-types',[],'managed dependency types'),softApi('/api/v1/application-platform/workspace-profiles',[],'workspace profiles'),softApi('/api/v1/application-platform/releases',[],'application releases'),softApi('/api/v1/application-platform/environment-bindings',[],'environment bindings')]);
    Object.assign(state,{projects,blueprintReleases:releases,variableSchemas:schemas,platformPolicySets:policies,platformTemplates:templates,applicationWorkloadTypes,applicationCapabilityTraits,applicationResourceTypes,applicationWorkspaceProfiles,applicationReleases,applicationEnvironmentBindings});
    renderPlatformTemplateAuthorities();
  }catch(error){$('#platform-template-grid').innerHTML=errorState(error.message);toast(error.message,'error');}
}
function parseTemplateJSON(id,label){try{const value=JSON.parse($(id).value.trim());if(!Array.isArray(value))throw new Error(`${label} must be a JSON array.`);return value;}catch(error){throw new Error(`${label}: ${error.message}`);}}
$('#template-schema-form').onsubmit=async event=>{event.preventDefault();const form=event.currentTarget;if(!form.reportValidity())return;try{await api('/api/v1/variable-schemas',{method:'POST',body:{projectId:$('#template-schema-project').value,name:$('#template-schema-name').value.trim(),version:$('#template-schema-version').value.trim(),variables:parseTemplateJSON('#template-schema-variables','Variable definitions')}});toast('Immutable variable schema created.');form.reset();await loadPlatformTemplates();}catch(error){toast(error.message,'error');}};
$('#template-policy-form').onsubmit=async event=>{event.preventDefault();const form=event.currentTarget;if(!form.reportValidity())return;try{const required=$('#template-policy-backup-required').checked;await api('/api/v1/platform-policy-sets',{method:'POST',body:{projectId:$('#template-policy-project').value,name:$('#template-policy-name').value.trim(),version:$('#template-policy-version').value.trim(),maintenance:{riskClass:$('#template-policy-risk').value,requireApproval:$('#template-policy-approval').checked,maxUnavailable:Number($('#template-policy-max-unavailable').value),requireRecoveryCheckpoint:$('#template-policy-checkpoint').checked},backup:{required,provider:required?$('#template-policy-backup-provider').value.trim():'',schedule:required?$('#template-policy-backup-schedule').value.trim():'',retention:required?$('#template-policy-backup-retention').value.trim():''},security:{podSecurityLevel:$('#template-policy-security').value,defaultDenyIngress:$('#template-policy-deny-ingress').checked,defaultDenyEgress:$('#template-policy-deny-egress').checked,allowDNS:$('#template-policy-allow-dns').checked}}});toast('Immutable policy set created.');form.reset();await loadPlatformTemplates();}catch(error){toast(error.message,'error');}};
$('#platform-template-form').onsubmit=async event=>{event.preventDefault();const form=event.currentTarget;if(!form.reportValidity())return;try{const targets=$('#platform-template-targets').value.split(',').map(v=>v.trim()).filter(Boolean),certificationRequirements=$$('[data-template-cert]:checked').map(el=>el.value);if(!certificationRequirements.length)throw new Error('Select at least one certification requirement.');await api('/api/v1/platform-templates',{method:'POST',body:{projectId:$('#platform-template-project').value,name:$('#platform-template-name').value.trim(),version:$('#platform-template-version').value.trim(),blueprintReleaseId:$('#platform-template-blueprint').value,variableSchemaId:$('#platform-template-schema').value,policySetId:$('#platform-template-policy').value,allowedTargetClasses:targets,certificationRequirements}});toast('Immutable Platform Template created.');form.reset();$$('[data-template-cert]').forEach(el=>el.checked=true);await loadPlatformTemplates();}catch(error){toast(error.message,'error');}};
$('#platform-template-project').addEventListener('change',renderPlatformTemplateOptions);
$('#application-resolution-workload').addEventListener('change',renderApplicationPlatformComposition);
$('#application-promotion-binding').addEventListener('change',renderApplicationPlatformComposition);
$('#application-resolution-form').onsubmit=async event=>{event.preventDefault();const workloadId=$('#application-resolution-workload').value;if(!workloadId)return;const workload=state.applicationWorkloadTypes.find(item=>item.id===workloadId);const traitIds=[...$('#application-resolution-traits').selectedOptions].map(option=>option.value);const observedNativeCapabilities=$('#application-resolution-native').value.split(',').map(v=>v.trim()).filter(Boolean);try{const result=await api('/api/v1/application-platform/resolve',{method:'POST',body:{projectId:workload.projectId,workloadTypeId:workloadId,traitIds,observedNativeCapabilities}});$('#application-composition-result').innerHTML=`<div class="inline-summary"><strong>Capability resolution preview</strong> · ${esc(shortDigest(result.resolutionDigest))}<br>${(result.decisions||[]).map(row=>`${badge(row.action)} ${esc(row.capability)} — ${esc(row.reason)}`).join('<br>')||'No traits selected.'}<br><small>Preview only. No target or desired binding was mutated.</small></div>`;}catch(error){toast(error.message,'error');}};
$('#application-promotion-form').onsubmit=async event=>{event.preventDefault();const binding=state.applicationEnvironmentBindings.find(item=>item.id===$('#application-promotion-binding').value),release=state.applicationReleases.find(item=>item.id===$('#application-promotion-release').value);if(!binding||!release)return;if(binding.projectId!==release.projectId){toast('Release and environment binding must belong to the same project.','error');return;}const observedNativeCapabilities=$('#application-promotion-native').value.split(',').map(v=>v.trim()).filter(Boolean);if(!await confirmAction('Promote environment release',`Advance ${binding.environment} / ${binding.namespace} from its current immutable release to ${release.name} ${release.version}? The WorkspaceBinding scope cannot change and will be revalidated before commit.`,false))return;try{await api(`/api/v1/application-platform/environment-bindings/${encodeURIComponent(binding.id)}/promote`,{method:'POST',headers:{'If-Match':`"${binding.revision}"`},body:{releaseId:release.id,observedNativeCapabilities}});toast('Environment binding promoted. Runtime convergence and Physical certification remain separate.');await loadPlatformTemplates();}catch(error){toast(error.message,'error');}};
$('#templates').addEventListener('click',async event=>{const inspect=event.target.closest('[data-application-inspect]');if(inspect){const kind=inspect.dataset.applicationInspect;let item=null;if(kind==='workload')item=state.applicationWorkloadTypes.find(row=>row.id===inspect.dataset.id);if(kind==='release')item=state.applicationReleases.find(row=>row.id===inspect.dataset.id);if(kind==='binding')item=state.applicationEnvironmentBindings.find(row=>row.id===inspect.dataset.id);if(item){showDetails('Application composition authority',`<div class="warning-banner">Desired authority only. Rendered/observed runtime and Exact-SHA Physical certification remain independent.</div><dl class="key-value">${Object.entries(item).filter(([key,value])=>value!==null&&value!==undefined&&typeof value!=='object').map(([key,value])=>`<dt>${esc(key)}</dt><dd class="${String(key).toLowerCase().includes('digest')||String(key).toLowerCase().includes('id')?'technical':''}">${esc(value)}</dd>`).join('')}</dl>`);}return;}const button=event.target.closest('[data-template-admission]');if(!button)return;try{const result=await api(`/api/v1/platform-templates/${button.dataset.templateAdmission}/admission?targetClass=${encodeURIComponent(button.dataset.targetClass||'')}`);$('#platform-template-admission-result').innerHTML=`<div class="${result.blockers?.length?'warning-banner':'inline-summary'}"><strong>Source admission</strong> · binding ${result.bindingValid?'valid':'invalid'} · target ${result.targetAllowed?'allowed':'blocked'} · adoption ready <strong>${result.adoptionReady?'YES':'NO'}</strong> · impact ${esc(result.impactStatus)}${result.blockers?.length?`<br>Blockers: ${esc(result.blockers.join(', '))}`:''}<br><small>Even with zero source blockers, adoptionReady remains false until target-specific impact and required certification evidence exist.</small></div>`;}catch(error){toast(error.message,'error');}});

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
  const upstream=summary.upstreamAdmission||{total:0,readyForAcquisition:0,reviewRequired:0,runtimeBlocked:0,components:[]};
  $('#catalog-summary').innerHTML=[['Components',summary.componentCount||state.catalog.length,`${summary.resolvedComponentCount||0} resolved · ${summary.unresolvedComponentCount??state.catalog.filter(c=>!c.spec?.source?.resolved).length} unresolved`],['Renderable',summary.renderableComponentCount||0,'embedded source bundles verified at startup'],['S1 acquisition',`${upstream.readyForAcquisition||0}/${upstream.total||0}`,`${upstream.reviewRequired||0} source-selection reviews · ${upstream.runtimeBlocked||0} runtime holds`],['Governed releases',state.catalogReleases.length,`${published} published`],['Active trust keys',activeKeys,'Ed25519 verification authority'],['Catalog digest',shortDigest(summary.digest||''),'shipped inventory digest']].map(([label,value,detail])=>`<article class="metric-card"><strong${label==='Catalog digest'?' class="technical"':''}>${esc(value)}</strong><span>${esc(label)}</span><small>${esc(detail)}</small></article>`).join('');
  const upstreamRows=Array.isArray(upstream.components)?upstream.components:[];
  $('#catalog-upstream-admission').innerHTML=upstreamRows.length?`${upstream.reviewRequired?`<div class="warning-banner"><strong>${esc(upstream.reviewRequired)} source-selection review${upstream.reviewRequired===1?'':'s'} remain blocked</strong> · ${esc(upstream.readyForAcquisition||0)} exact candidates are acquisition-ready.</div>`:upstream.runtimeBlocked?`<div class="warning-banner"><strong>Source admission closed</strong> · all ${esc(upstream.readyForAcquisition||0)} candidates may be acquired, while ${esc(upstream.runtimeBlocked||0)} runtime hold${upstream.runtimeBlocked===1?'':'s'} remain fail-closed until separate certification clears them.</div>`:`<div class="success-banner"><strong>Source admission closed</strong> · every unresolved upstream component has an exact acquisition candidate. Immutable acquisition and runtime certification remain separate gates.</div>`}<div class="activity-list">${upstreamRows.map(row=>{const selected=row.selectedVersion||row.catalogConstraint||'unselected',sourceBlocked=row.status!=='ready-for-acquisition',runtimeBlocked=row.runtimeStatus&&row.runtimeStatus!=='eligible-after-source-resolution',evidence=Array.isArray(row.reviewEvidence)?row.reviewEvidence:[];return `<div class="activity-item"><div class="activity-main"><span class="check-icon">${sourceBlocked?'!':runtimeBlocked?'~':'✓'}</span><div><strong>${esc(row.component)} · ${esc(selected)}</strong><small>${esc(row.rationale||'No rationale')}</small>${evidence.length?`<details><summary>Review evidence · ${esc(evidence.length)}</summary><div class="resource-details">${evidence.map(item=>`${detailRow('Kind',item.kind||'evidence')}${detailRow('Evidence',item.url||'—',true)}${detailRow('Finding',item.summary||'—')}`).join('')}</div></details>`:''}</div></div><div class="resource-meta">${badge(row.status||'UNKNOWN')}${badge(row.runtimeStatus||'UNKNOWN')}</div></div>`;}).join('')}</div>`:emptyState('No upstream admission rows','All shipped components are already source-resolved or the admission authority has no unresolved Helm rows.');
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


let edgeCompiledPolicy=null;
let edgeLastMutationRequest=null;
function renderEdgeAssessment(target,data){
  target.innerHTML='<pre class="technical">'+esc(JSON.stringify(data,null,2))+'</pre>';
}
function edgeProjectID(){
  return String($('#edge-project')?.value||'').trim();
}
async function loadEdgeSovereign(){
  const projects=await softApi('/api/v1/projects',[],'projects');
  state.projects=projects;
  setProjectOptions($('#edge-project'),projects);
  prerequisite($('#edge-prerequisite'),projects.length>0,'Create or select a project before reviewing edge authority.','workspace','Open organizations & projects');
  const now=new Date();
  if(!$('#edge-policy-valid-until').value)$('#edge-policy-valid-until').value=localDateTimeValue(new Date(now.getTime()+24*60*60*1000));
  if(!$('#edge-disconnected-since').value)$('#edge-disconnected-since').value=localDateTimeValue(new Date(now.getTime()-5*60*1000));
}
$('#edge-policy-form').onsubmit=async event=>{
  event.preventDefault();if(!event.currentTarget.reportValidity())return;
  const projectId=edgeProjectID();if(!projectId){toast('Select a project first.','error');return;}
  const allowedActions=$('[data-edge-action]:checked',event.currentTarget).map(input=>input.value);
  try{
    const result=await api('/api/v1/edge/local-authority/policies/compile',{method:'POST',body:{
      projectId,siteId:$('#edge-policy-site').value.trim(),revision:Number($('#edge-policy-revision').value),
      desiredStateDigest:$('#edge-policy-desired-digest').value.trim(),allowedActions,
      maxOfflineSeconds:Number($('#edge-policy-offline').value),maxQueuedEvidenceItems:Number($('#edge-policy-evidence').value),
      validUntil:new Date($('#edge-policy-valid-until').value).toISOString()
    }});
    edgeCompiledPolicy=result.policy;edgeLastMutationRequest=null;
    $('#edge-mutation-target').value='site:'+edgeCompiledPolicy.siteId;
    $('#edge-reconnect-revision').value=String(edgeCompiledPolicy.revision);
    $('#edge-reconnect-digest').value=edgeCompiledPolicy.desiredStateDigest;
    renderEdgeAssessment($('#edge-policy-result'),result);toast('Edge policy compiled. No runtime mutation was executed.');
  }catch(error){renderEdgeAssessment($('#edge-policy-result'),{admitted:false,error:error.message,code:error.code||''});toast(error.message,'error');}
};
$('#edge-mutation-form').onsubmit=async event=>{
  event.preventDefault();if(!event.currentTarget.reportValidity())return;
  if(!edgeCompiledPolicy){toast('Compile a site-local policy first.','warning');return;}
  const projectId=edgeProjectID();
  const request={siteId:edgeCompiledPolicy.siteId,projectId,action:$('#edge-mutation-action').value,targetRef:$('#edge-mutation-target').value.trim(),baseRevision:edgeCompiledPolicy.revision,baseDesiredDigest:edgeCompiledPolicy.desiredStateDigest,policyDigest:edgeCompiledPolicy.policyDigest,idempotencyKey:$('#edge-mutation-idempotency').value.trim(),requestDigest:$('#edge-mutation-request-digest').value.trim()};
  try{
    const result=await api('/api/v1/edge/local-authority/mutations/admit',{method:'POST',body:{projectId,policy:edgeCompiledPolicy,request,disconnectedSince:new Date($('#edge-disconnected-since').value).toISOString()}});
    edgeLastMutationRequest=request;renderEdgeAssessment($('#edge-mutation-result'),result);toast('Offline request fits the policy. Execution still requires a durable operation.');
  }catch(error){renderEdgeAssessment($('#edge-mutation-result'),{admitted:false,error:error.message,code:error.code||''});toast(error.message,'error');}
};
$('#edge-reconnect-form').onsubmit=async event=>{
  event.preventDefault();if(!event.currentTarget.reportValidity())return;
  if(!edgeLastMutationRequest){toast('Assess an offline request first.','warning');return;}
  const projectId=edgeProjectID();
  try{
    const result=await api('/api/v1/edge/local-authority/reconnect/resolve',{method:'POST',body:{projectId,request:edgeLastMutationRequest,centralRevision:Number($('#edge-reconnect-revision').value),centralDesiredStateDigest:$('#edge-reconnect-digest').value.trim()}});
    renderEdgeAssessment($('#edge-reconnect-result'),result);
    toast(result?.decision?.automaticApply?'No central drift detected.':'Central drift requires review.',result?.decision?.automaticApply?'success':'warning');
  }catch(error){renderEdgeAssessment($('#edge-reconnect-result'),{error:error.message,code:error.code||''});toast(error.message,'error');}
};
$('#edge-boot-form').onsubmit=async event=>{
  event.preventDefault();if(!event.currentTarget.reportValidity())return;const projectId=edgeProjectID();if(!projectId){toast('Select a project first.','error');return;}
  const claim={authority:'BOOT_SECURITY_ATTESTATION_AUTHORITY_V1',siteId:$('#edge-boot-site').value.trim(),nodeId:$('#edge-boot-node').value.trim(),observedAt:new Date().toISOString(),tpmPresent:$('#edge-boot-tpm').checked,secureBootEnabled:$('#edge-boot-secure').checked,measuredBootPresent:$('#edge-boot-measured').checked,diskEncryptionVerified:$('#edge-boot-encrypted').checked,quoteVerified:$('#edge-boot-quote-ok').checked,nonceBound:$('#edge-boot-nonce').checked,pcrPolicyMatched:$('#edge-boot-pcr').checked,quoteDigest:$('#edge-boot-quote').value.trim(),eventLogDigest:$('#edge-boot-event').value.trim(),evidenceDigest:$('#edge-boot-evidence').value.trim()};
  try{const result=await api('/api/v1/edge/boot-attestations/assess',{method:'POST',body:{projectId,claim}});renderEdgeAssessment($('#edge-boot-result'),result);toast(result?.assessment?.state==='ATTESTED'?'Boot claim satisfies the source policy.':'Boot claim was rejected.',result?.assessment?.state==='ATTESTED'?'success':'warning');}
  catch(error){renderEdgeAssessment($('#edge-boot-result'),{error:error.message,code:error.code||''});toast(error.message,'error');}
};
$('#edge-ai-form').onsubmit=async event=>{
  event.preventDefault();if(!event.currentTarget.reportValidity())return;const projectId=edgeProjectID();if(!projectId){toast('Select a project first.','error');return;}
  const profile={authority:'LOCAL_AI_DISCONNECTED_PROFILE_AUTHORITY_V1',mode:'disconnected',runtime:$('#edge-ai-runtime').value.trim(),modelDigest:$('#edge-ai-model').value.trim(),runtimeImageDigest:$('#edge-ai-image').value.trim(),networkEgress:false,rawCredentials:false,externalProvider:false,maxPromptBytes:Number($('#edge-ai-prompt').value),maxOutputBytes:Number($('#edge-ai-output').value)};
  try{const result=await api('/api/v1/edge/local-ai/profiles/validate',{method:'POST',body:{projectId,profile}});renderEdgeAssessment($('#edge-ai-result'),result);toast('Disconnected local AI profile is source-admitted; runtime was not started.');}
  catch(error){renderEdgeAssessment($('#edge-ai-result'),{admitted:false,error:error.message,code:error.code||''});toast(error.message,'error');}
};

const loaders={overview:loadOverview,workspace:loadWorkspace,installation:loadInstallation,clusters:loadClusters,providers:loadProviders,blueprints:loadBlueprints,templates:loadPlatformTemplates,marketplace:loadMarketplace,baselines:loadBaselines,verification:loadVerification,fleet:loadFleet,workspaces:loadWorkspaces,finops:loadFinOps,edge:loadEdgeSovereign,tenants:loadTenants,operations:loadOperations,ai:loadAI,lab:loadLab,notifications:loadNotifications,services:loadServices,catalog:loadCatalog,validator:async()=>{}};
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
