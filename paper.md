3.4.2 数据库逻辑模型设计

根据概念模型，设计数据库的具体表结构。以下是主要数据表的设计：

**用户表（User）**

| 字段名 | 数据类型 | 说明 | 约束 |
|------------|--------------|-------------|------------------|
| id | Integer | 用户ID | 主键，自增 |
| username | Varchar(50) | 用户名 | 唯一，非空 |
| password | Varchar(128) | 密码 | 非空 |
| email | Varchar(254) | 邮箱 | 可空 |
| is_active | Boolean | 是否激活 | 默认True |
| is_admin | Boolean | 是否管理员 | 默认False |
| created_at | Datetime | 创建时间 | 自动添加当前时间 |
| last_login | Datetime | 最后登录时间 | 可空 |

**用户日志表（UserLog）**

| 字段名 | 数据类型 | 说明 | 约束 |
|------------|--------------|-------------|-------------------|
| id | Integer | 日志ID | 主键，自增 |
| user_id | Integer | 用户ID | 外键(User.id) |
| action | Varchar(100) | 操作内容 | 非空 |
| ip | Varchar(50) | IP地址 | 可空 |
| details | Text | 详细信息 | 可空 |
| created_at | Datetime | 操作时间 | 自动添加当前时间 |

**基础信息查询表（BaseInfoQuery）**

| 字段名 | 数据类型 | 说明 | 约束 |
|------------|--------------|-------------|-------------------|
| id | Integer | 查询ID | 主键，自增 |
| domain | Varchar(255) | 域名 | 非空 |
| has_cdn | Boolean | 是否有CDN | 默认False |
| ip_list | Text | IP列表 | 可空，JSON格式 |
| whois_info | Text | WHOIS信息 | 可空，JSON格式 |
| icp_info | Text | 备案信息 | 可空，JSON格式 |
| query_time | Datetime | 查询时间 | 自动添加当前时间 |

**端口扫描表（PortScan）**

| 字段名 | 数据类型 | 说明 | 约束 |
|------------|--------------|-------------|-------------------|
| id | Integer | 扫描ID | 主键，自增 |
| target | Varchar(255) | 扫描目标 | 非空 |
| scan_type | Varchar(50) | 扫描类型 | 默认'connect' |
| ports | Text | 端口范围 | 可空 |
| status | Varchar(20) | 扫描状态 | 非空 |
| result | Text | 扫描结果 | 可空，JSON格式 |
| start_time | Datetime | 开始时间 | 自动添加当前时间 |
| end_time | Datetime | 结束时间 | 可空 |

**目录扫描表（DirScan）**

| 字段名 | 数据类型 | 说明 | 约束 |
|---------------|--------------|-------------|-------------------|
| id | Integer | 扫描ID | 主键，自增 |
| target | Varchar(255) | 扫描目标 | 非空 |
| wordlist | Varchar(100) | 字典类型 | 默认'common' |
| status | Varchar(20) | 扫描状态 | 非空 |
| result | Text | 扫描结果 | 可空，JSON格式 |
| start_time | Datetime | 开始时间 | 自动添加当前时间 |
| end_time | Datetime | 结束时间 | 可空 |
| extensions | Varchar(255) | 文件扩展名 | 可空 |
| threads | Integer | 线程数 | 默认10 |
| timeout | Integer | 超时时间 | 默认10(秒) |
| status_codes | Varchar(100) | 状态码过滤 | 可空 |
| user_agent | Varchar(255) | User-Agent | 可空 |

**指纹分类表（FingerprintCategory）**

| 字段名 | 数据类型 | 说明 | 约束 |
|-------------|--------------|-------------|-------------------|
| id | Integer | 分类ID | 主键，自增 |
| name | Varchar(100) | 分类名称 | 唯一，非空 |
| description | Text | 分类描述 | 可空 |
| create_time | Datetime | 创建时间 | 自动添加当前时间 |
| update_time | Datetime | 更新时间 | 自动更新为当前时间 |

**指纹表（Fingerprint）**

| 字段名 | 数据类型 | 说明 | 约束 |
|-------------|--------------|-------------|-------------------------|
| id | Integer | 指纹ID | 主键，自增 |
| name | Varchar(100) | 指纹名称 | 非空 |
| category_id | Integer | 所属分类ID | 外键(FingerprintCategory.id) |
| rule | Varchar(255) | 匹配规则 | 非空 |
| position | Varchar(20) | 匹配位置 | 非空，枚举值 |
| description | Text | 指纹描述 | 可空 |
| create_time | Datetime | 创建时间 | 自动添加当前时间 |
| update_time | Datetime | 更新时间 | 自动更新为当前时间 |

**指纹扫描表（FingerprintScan）**

| 字段名 | 数据类型 | 说明 | 约束 |
|------------|--------------|-------------|-------------------|
| id | Integer | 扫描ID | 主键，自增 |
| target | Varchar(255) | 扫描目标 | 非空 |
| status | Varchar(20) | 扫描状态 | 非空 |
| result | Text | 扫描结果 | 可空，JSON格式 |
| start_time | Datetime | 开始时间 | 自动添加当前时间 |
| end_time | Datetime | 结束时间 | 可空 |

**子域名表（Subdomain）**

| 字段名 | 数据类型 | 说明 | 约束 |
|-------------|--------------|-------------|-------------------------|
| id | Integer | 记录ID | 主键，自增 |
| domain | Varchar(255) | 主域名 | 非空 |
| subdomain | Varchar(255) | 子域名 | 非空 |
| ip | Varchar(100) | IP地址 | 可空 |
| status | Integer | 状态码 | 可空，默认200 |
| title | Varchar(255) | 网站标题 | 可空 |
| server | Varchar(255) | 服务器 | 可空 |
| create_time | Datetime | 创建时间 | 自动添加当前时间 |
| update_time | Datetime | 更新时间 | 自动更新为当前时间 |

**POC分类表（PocCategory）**

| 字段名 | 数据类型 | 说明 | 约束 |
|-------------|--------------|-------------|-------------------|
| id | Integer | 分类ID | 主键，自增 |
| name | Varchar(100) | 分类名称 | 唯一，非空 |
| description | Text | 分类描述 | 可空 |
| create_time | Datetime | 创建时间 | 自动添加当前时间 |
| update_time | Datetime | 更新时间 | 自动更新为当前时间 |

**POC表（Poc）**

| 字段名 | 数据类型 | 说明 | 约束 |
|-------------|--------------|-------------|---------------------|
| id | Integer | POC ID | 主键，自增 |
| name | Varchar(100) | POC名称 | 非空 |
| category_id | Integer | 所属分类ID | 外键(PocCategory.id) |
| template | Text | Nuclei模板 | 非空 |
| severity | Varchar(20) | 危害等级 | 非空，枚举值 |
| description | Text | POC描述 | 可空 |
| create_time | Datetime | 创建时间 | 自动添加当前时间 |
| update_time | Datetime | 更新时间 | 自动更新为当前时间 |

**漏洞扫描表（VulnScan）**

| 字段名 | 数据类型 | 说明 | 约束 |
|--------------|--------------|-------------|-------------------|
| id | Integer | 扫描ID | 主键，自增 |
| target | Varchar(255) | 扫描目标 | 非空 |
| status | Varchar(20) | 扫描状态 | 非空 |
| result | Text | 扫描结果 | 可空，JSON格式 |
| start_time | Datetime | 开始时间 | 自动添加当前时间 |
| end_time | Datetime | 结束时间 | 可空 |
| found_count | Integer | 发现漏洞数量 | 默认0 |
| templates | Varchar(255) | 模板 | 可空 |
| severity | Varchar(255) | 危害等级 | 可空 |
| threads | Integer | 线程数 | 默认10 |
| timeout | Integer | 超时时间 | 默认5(分钟) |

**扫描报告表（ScanReport）**

| 字段名 | 数据类型 | 说明 | 约束 |
|--------------|--------------|-------------|-------------------|
| id | Integer | 报告ID | 主键，自增 |
| title | Varchar(255) | 报告标题 | 非空 |
| report_type | Varchar(20) | 报告类型 | 非空，枚举值 |
| target | Varchar(255) | 扫描目标 | 非空 |
| scan_time | Datetime | 扫描时间 | 非空 |
| content | Text | 报告内容 | 非空，JSON格式 |
| create_time | Datetime | 创建时间 | 自动添加当前时间 |
| update_time | Datetime | 更新时间 | 自动更新为当前时间 |

**漏洞报告表（VulnerabilityReport）**

| 字段名 | 数据类型 | 说明 | 约束 |
|--------------|--------------|-------------|-------------------|
| id | Integer | 报告ID | 主键，自增 |
| title | Varchar(255) | 报告标题 | 非空 |
| target | Varchar(255) | 目标 | 非空 |
| severity | Varchar(20) | 危害等级 | 非空，枚举值 |
| description | Text | 漏洞描述 | 非空 |
| solution | Text | 修复建议 | 非空 |
| poc | Text | 验证POC | 可空 |
| create_time | Datetime | 创建时间 | 自动添加当前时间 |
| update_time | Datetime | 更新时间 | 自动更新为当前时间 |

**系统公告表（Notice）**

| 字段名 | 数据类型 | 说明 | 约束 |
|-------------|--------------|-------------|-------------------|
| id | Integer | 公告ID | 主键，自增 |
| title | Varchar(200) | 公告标题 | 非空 |
| content | Text | 公告内容 | 非空 |
| created_at | Datetime | 创建时间 | 自动添加当前时间 |
| updated_at | Datetime | 更新时间 | 自动更新为当前时间 |
| is_active | Boolean | 是否激活 | 默认True |
