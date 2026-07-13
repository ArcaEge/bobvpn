pub const SITE_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #fafafa;
            color: #333;
            line-height: 1.6;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
        }
        header {
            padding: 3rem 0 2rem;
            border-bottom: 1px solid #eee;
            margin-bottom: 2rem;
        }
        h1 { font-size: 1.8rem; font-weight: 600; color: #111; }
        .subtitle { color: #666; margin-top: 0.5rem; font-size: 1rem; }
        main { padding: 1rem 0; }
        .card {
            background: #fff;
            border: 1px solid #e8e8e8;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }
        .card h2 { font-size: 1.1rem; margin-bottom: 0.5rem; }
        .card p { color: #555; font-size: 0.95rem; }
        footer {
            margin-top: 3rem;
            padding: 1.5rem 0;
            border-top: 1px solid #eee;
            color: #999;
            font-size: 0.85rem;
        }
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>My Site</h1>
        <p class="subtitle">Just a simple page.</p>
    </header>
    <main>
        <div class="card">
            <h2>About</h2>
            <p>This site is under construction. Check back later.</p>
        </div>
        <div class="card">
            <h2>Contact</h2>
            <p>Reach out via email for inquiries.</p>
        </div>
    </main>
    <footer>&copy; 2026. All rights reserved.</footer>
</div>
</body>
</html>"#;
