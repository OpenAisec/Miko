# Ruby on Rails Security Audit Guide

> Ruby on Rails 框架安全审计模块
> 适用于: Rails 6.x/7.x/8.x, ActiveRecord, ActionPack, ActiveStorage

## 识别特征

```ruby
# Rails 项目识别
require "rails"
Rails.application
class ApplicationController < ActionController::Base

# 文件结构
├── Gemfile / Gemfile.lock
├── config/
│   ├── routes.rb
│   ├── application.rb
│   ├── environments/ (production.rb, development.rb)
│   └── initializers/
├── app/
│   ├── controllers/
│   ├── models/
│   ├── views/ (*.html.erb)
│   └── jobs/
├── db/
│   ├── schema.rb
│   └── migrate/
└── config.ru
```

---

## SQL 注入检测

```ruby
# 危险: where() 字符串插值
User.where("name = '#{params[:name]}'")           # ❌ Critical
User.where("role = '#{role}' AND active = true")  # ❌

# 危险: find_by_sql 拼接
User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")  # ❌ Critical

# 危险: order() 用户输入
User.order(params[:sort])  # ❌ High: ORDER BY 注入 (可CASE盲注)
# 攻击: ?sort=CASE WHEN (SELECT 1 FROM users WHERE name='admin' AND password LIKE 'a%') THEN name ELSE email END

# 危险: pluck/select 拼接
User.pluck(params[:column])                 # ❌
User.select("#{params[:field]} as value")   # ❌

# 危险: group / having / joins
User.group(params[:group_by])               # ❌
User.joins(params[:table])                  # ❌
User.having("count > #{params[:count]}")    # ❌

# 危险: execute 直接执行
ActiveRecord::Base.connection.execute("DELETE FROM logs WHERE id = #{id}")  # ❌

# 审计正则
\.where\s*\(.*#\{|\.where\s*\(.*\+
find_by_sql\s*\(.*#\{|find_by_sql\s*\(.*\+
\.order\s*\(params|\.order\s*\(.*#\{
\.pluck\s*\(params|\.select\s*\(.*#\{
\.execute\s*\(.*#\{|\.execute\s*\(.*\+

# 安全: 参数化查询
User.where("name = ?", params[:name])              # ✓
User.where(name: params[:name])                    # ✓ Hash条件
User.find_by_sql(["SELECT * FROM users WHERE id = ?", params[:id]])  # ✓
User.order(Arel.sql(sanitize_sql_for_order(params[:sort])))          # ✓ 白名单

# order 安全: 白名单
ALLOWED_SORT = %w[name email created_at].freeze
sort_col = ALLOWED_SORT.include?(params[:sort]) ? params[:sort] : "id"
User.order(sort_col)  # ✓
```

---

## Mass Assignment (强参数绕过)

```ruby
# 危险: permit! 允许所有参数
def user_params
  params.require(:user).permit!  # ❌ Critical: 等同于无防护
end

# 危险: 过于宽泛的permit
params.require(:user).permit(:name, :email, :role, :is_admin)  # ❌ role/is_admin不应允许

# 危险: 直接使用params哈希
User.create(params[:user])             # ❌ Rails 4+ 会报错, 但老代码可能绕过
User.update(params.permit(:name).to_h) # ❌ 如果其他地方又添加了字段

# 审计正则
\.permit!|\.permit\(.*:role|\.permit\(.*:admin|\.permit\(.*:is_admin
params\[:.*\]\.to_unsafe_h|params\.to_unsafe_hash

# 安全: 严格强参数
def user_params
  params.require(:user).permit(:name, :email, :bio)  # ✓ 仅允许安全字段
end
```

---

## CSRF 保护绕过

```ruby
# 危险: 跳过CSRF验证
class ApiController < ApplicationController
  skip_before_action :verify_authenticity_token  # ❌ High: 全控制器跳过CSRF
end

# 危险: 全局禁用
class ApplicationController < ActionController::Base
  protect_from_forgery with: :null_session  # ❌ Medium: API模式下需确认
end

# 危险: 特定action跳过
skip_before_action :verify_authenticity_token, only: [:webhook]  # 需确认是否合理

# 审计正则
skip_before_action\s*:verify_authenticity_token
protect_from_forgery.*:null_session|protect_from_forgery.*:exception

# 安全: 默认启用
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception  # ✓ CSRF失败抛异常
end
```

---

## 不安全的反序列化

```ruby
# 危险: Marshal.load 用户输入
data = Marshal.load(params[:data])       # ❌ Critical: RCE
data = Marshal.load(Base64.decode64(cookie_value))  # ❌

# 危险: YAML.load (Ruby < 3.1 默认不安全)
config = YAML.load(user_input)           # ❌ Critical: RCE (Psych < 4.0)
YAML.load(File.read(user_controlled))    # ❌

# 危险: JSON.parse + 自定义类
data = JSON.parse(input, create_additions: true)  # ❌ 允许实例化任意类

# 审计正则
Marshal\.load|Marshal\.restore
YAML\.load\s*\((?!.*permitted_classes)
JSON\.parse\s*\(.*create_additions.*true

# 安全: 安全替代
YAML.safe_load(input)                           # ✓ 仅允许基本类型
YAML.safe_load(input, permitted_classes: [Date]) # ✓ 明确白名单
JSON.parse(input)                               # ✓ 默认安全 (无create_additions)
```

---

## 命令注入

```ruby
# 危险: system / exec / backticks
system("convert #{params[:file]} output.png")    # ❌ Critical
`ls #{params[:dir]}`                             # ❌ Critical
exec("ping #{params[:host]}")                    # ❌ Critical
%x(nslookup #{user_input})                       # ❌

# 危险: Open3
Open3.capture2("grep #{pattern} /var/log/app")   # ❌
IO.popen("cat #{filename}")                      # ❌

# 危险: Kernel.open (Ruby < 2.7 支持管道)
open("|#{params[:cmd]}")                         # ❌ Critical: 管道执行
open(params[:url])                               # ❌ 可用 |command 触发

# 审计正则
system\s*\(.*#\{|`.*#\{.*`|exec\s*\(.*#\{
%x\(.*#\{|Open3\.(capture|popen)\s*\(.*#\{
IO\.popen\s*\(.*#\{|Kernel\.open\s*\(.*params

# 安全: 数组形式传参 (不经过shell)
system("convert", params[:file], "output.png")     # ✓ 数组形式
Open3.capture2("grep", pattern, "/var/log/app")    # ✓
```

---

## render() 内容类型注入

```ruby
# 危险: render inline 用户输入 (SSTI)
render inline: params[:template]         # ❌ Critical: ERB代码执行
render inline: user_input, type: :erb    # ❌ Critical

# 危险: render file 路径遍历
render file: params[:page]               # ❌ High: 任意文件读取
render template: params[:tpl]            # ❌

# 危险: render body/html 拼接
render html: "<p>#{params[:msg]}</p>".html_safe  # ❌ XSS

# 审计正则
render\s+inline:|render\s+file:\s*params|render\s+template:\s*params
render\s+html:.*html_safe

# 安全: 使用模板
render template: "pages/#{safe_page}"    # ✓ 白名单验证后
render json: { message: params[:msg] }   # ✓ JSON自动编码
```

---

## ActiveStorage 路径遍历

```ruby
# 危险: 用户控制的content_disposition/filename
blob = ActiveStorage::Blob.find_signed(params[:id])
send_data blob.download,
  filename: params[:filename],              # ❌ 可能含路径遍历字符
  disposition: params[:disposition]          # ❌ 可注入响应头

# 审计正则
send_data.*params\[:.*filename|send_file.*params

# 安全: 使用blob自带属性
send_data blob.download,
  filename: blob.filename.to_s,            # ✓ 使用存储时的文件名
  disposition: "attachment"                 # ✓ 硬编码
```

---

## Session 安全

```ruby
# 危险: 未重置Session (会话固定)
def login
  user = User.authenticate(params[:email], params[:password])
  session[:user_id] = user.id  # ❌ 未先调用reset_session
end

# 危险: 弱session存储
Rails.application.config.session_store :cookie_store,
  key: '_app_session'  # Cookie存储在客户端, 需确保secret_key_base强度

# 审计正则
session\[:.*\]\s*=(?!.*reset_session)
secret_key_base.*=.*['"][^'"]{0,30}['"]

# 安全: 登录时重置session
def login
  user = User.authenticate(params[:email], params[:password])
  reset_session                    # ✓ 防止会话固定
  session[:user_id] = user.id
end
```

---

## 搜索模式汇总

```regex
# SQL注入
\.where\s*\(.*#\{|find_by_sql\s*\(.*#\{|\.order\s*\(params
\.execute\s*\(.*#\{|\.pluck\s*\(params|\.select\s*\(.*#\{

# Mass Assignment
\.permit!|params\[.*\]\.to_unsafe_h

# CSRF
skip_before_action.*verify_authenticity_token

# 反序列化
Marshal\.load|YAML\.load\s*\(|create_additions.*true

# 命令注入
system\s*\(.*#\{|`.*#\{.*`|Open3.*#\{|IO\.popen.*#\{

# render注入
render\s+inline:|render\s+file:\s*params

# Session
session\[:.*=(?!.*reset_session)

# 开放重定向
redirect_to\s*params|redirect_to\s*.*request
```

---

## 快速审计检查清单

```markdown
[ ] 检查 Rails 版本和已知CVE
[ ] 搜索 where/find_by_sql 字符串插值 (SQL注入)
[ ] 搜索 order(params[]) (ORDER BY 注入)
[ ] 搜索 .permit! 和宽泛permit列表 (Mass Assignment)
[ ] 搜索 skip_before_action :verify_authenticity_token (CSRF绕过)
[ ] 搜索 Marshal.load / YAML.load (反序列化)
[ ] 搜索 system/backticks/Open3 含插值 (命令注入)
[ ] 搜索 render inline/file 含用户输入 (SSTI/文件读取)
[ ] 检查 send_data/send_file 文件名来源
[ ] 搜索 login 流程中 reset_session 调用
[ ] 检查 secret_key_base 强度和存储
[ ] 搜索 html_safe / raw 用户输入 (XSS)
[ ] 搜索 redirect_to params[] (开放重定向)
[ ] 检查 config/environments/production.rb 安全配置
```

---

## 最小 PoC 示例
```bash
# SQL 注入 (where 插值)
curl "http://localhost:3000/users?name=admin'OR'1'='1"

# 命令注入
curl "http://localhost:3000/ping?host=127.0.0.1;id"

# 路径遍历 (render file)
curl "http://localhost:3000/page?file=../../../../etc/passwd"
```

---

## 参考资源

- [Rails Security Guide (Official)](https://guides.rubyonrails.org/security.html)
- [OWASP Ruby on Rails Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html)
- [Brakeman Scanner](https://brakemanscanner.org/)
- [Rails CVE List](https://www.cvedetails.com/vulnerability-list/vendor_id-12043/product_id-22568/Rubyonrails-Rails.html)
