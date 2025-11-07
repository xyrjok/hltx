<h3>配置数据库 (Cloudflare D1)</h3>
<p>-- 1. 商品分类 </p>
<pre class="language-sql"><code>CREATE TABLE Categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE
);</code></pre>
<p>-- 2. 商品</p>
<pre class="language-sql"><code>CREATE TABLE Products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category_id INTEGER,
    name TEXT NOT NULL,
    description TEXT,
    image_url TEXT,
    base_price REAL NOT NULL,
    FOREIGN KEY (category_id) REFERENCES Categories(id)
);</code></pre>
<p>-- 3. 商品规格 (库存)</p>
<pre class="language-sql"><code>CREATE TABLE ProductVariants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    price_adjustment REAL DEFAULT 0,
    stock_count INTEGER DEFAULT 0,
    FOREIGN KEY (product_id) REFERENCES Products(id) ON DELETE CASCADE
);</code></pre>
<p>-- 4. 文章</p>
<pre class="language-sql"><code>CREATE TABLE Articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    summary TEXT,
    content TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);</code></pre>
<p>-- 5. 卡密库存</p>
<pre class="language-sql"><code>CREATE TABLE Cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    variant_id INTEGER NOT NULL,
    card_key TEXT NOT NULL UNIQUE,
    is_used INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (variant_id) REFERENCES ProductVariants(id) ON DELETE CASCADE
);</code></pre>
<p>-- 6. 支付设置</p>
<pre class="language-sql"><code>CREATE TABLE PaymentSettings (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT
);</code></pre>
<p>-- 7. 网站配置&nbsp;</p>
<pre class="language-sql"><code>CREATE TABLE Configurations (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT
);</code></pre>
<p>-- 8. 订单</p>
<pre class="language-sql"><code>CREATE TABLE Orders (
    id TEXT PRIMARY KEY,
    variant_id INTEGER NOT NULL,
    total_amount REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    payment_id TEXT,
    delivered_card TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);</code></pre>

<h3>变量和机密</h3>		

| 类型   | 名称         | 值                          |
|--------|---------------|------------------------------|
| 纯文本 | ADMIN_PASS    | 123456                       |
| 纯文本 | ADMIN_TOKEN   | super-secret-admin-token-xyz  |
| 纯文本 | ADMIN_USER    | admin                        |



