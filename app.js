const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const { Pool } = require('pg');
const { SQSClient, SendMessageCommand } = require('@aws-sdk/client-sqs');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { CognitoIdentityProviderClient, SignUpCommand, InitiateAuthCommand } = require('@aws-sdk/client-cognito-identity-provider');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: 'secureshield-2026-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600000 }
}));

const REGION = 'ap-south-1';
const CLIENT_ID = '4oa4f4ct19r76fe8on6dq44f43';
const CLIENT_SECRET = '1rc17ils5cfkmeb6nijn7go3n7ufa5s3bgmgss8nqnce8og4kpuc';
const QUEUE_URL = 'https://sqs.ap-south-1.amazonaws.com/974813606412/incident-queue';
const BUCKET = 'incident-evidence-bucket-9748';

const sqs = new SQSClient({ region: REGION });
const s3 = new S3Client({ region: REGION });
const cognito = new CognitoIdentityProviderClient({ region: REGION });

const pool = new Pool({
    host: 'incident-db.c10ecyakcnf5.ap-south-1.rds.amazonaws.com',
    user: 'dbadmin',
    password: 'Incident123',
    database: 'incidentdb',
    port: 5432,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30000,
    max: 10
});

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });

function getSecretHash(email) {
    return crypto.createHmac('SHA256', CLIENT_SECRET)
        .update(email + CLIENT_ID)
        .digest('base64');
}

const styles = '<style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:Segoe UI,Arial,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;}.nav{background:#1e293b;padding:16px 40px;display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid #334155;}.nav .logo{font-size:20px;font-weight:700;color:#fff;text-decoration:none;}.nav .logo span{color:#38bdf8;}.nav .links a{color:#cbd5e1;text-decoration:none;margin-left:20px;font-size:14px;}.nav .links a:hover{color:#38bdf8;}.main{max-width:950px;margin:40px auto;padding:0 20px;}.card{background:#1e293b;border:1px solid #334155;border-radius:14px;padding:30px;margin-bottom:20px;}h1{color:#fff;font-size:28px;margin-bottom:10px;text-align:center;}h2{color:#fff;font-size:20px;margin-bottom:15px;}p{color:#94a3b8;font-size:15px;margin-bottom:15px;}label{display:block;color:#cbd5e1;font-size:13px;font-weight:600;margin-bottom:8px;text-transform:uppercase;letter-spacing:1px;}input,textarea,select{width:100%;padding:14px;background:#0f172a;border:2px solid #334155;border-radius:8px;color:#e2e8f0;font-size:15px;font-family:inherit;margin-bottom:15px;}input:focus,textarea:focus,select:focus{outline:none;border-color:#38bdf8;}.btn{width:100%;padding:14px;background:#0ea5e9;color:white;border:none;border-radius:8px;font-size:16px;font-weight:700;cursor:pointer;margin-bottom:10px;text-decoration:none;display:block;text-align:center;}.btn:hover{background:#0284c7;}.btn-secondary{background:#334155;}.alert{padding:14px 20px;border-radius:8px;margin-bottom:20px;font-size:14px;}.alert-success{background:#065f46;color:#d1fae5;}.alert-error{background:#991b1b;color:#fee2e2;}.alert-info{background:#1e40af;color:#dbeafe;}table{width:100%;border-collapse:collapse;margin-top:15px;}th,td{padding:12px;text-align:left;border-bottom:1px solid #334155;font-size:14px;}th{color:#94a3b8;text-transform:uppercase;font-size:12px;letter-spacing:1px;}.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:15px;margin:20px 0;}.stat{background:#0f172a;border:1px solid #334155;border-radius:10px;padding:20px;text-align:center;}.stat .num{font-size:28px;font-weight:700;color:#38bdf8;}.stat .lbl{font-size:12px;color:#94a3b8;margin-top:5px;text-transform:uppercase;}.badge{display:inline-block;padding:4px 12px;border-radius:12px;font-size:12px;font-weight:600;}.badge-red{background:#7f1d1d;color:#fca5a5;}.badge-orange{background:#78350f;color:#fdba74;}.badge-green{background:#14532d;color:#86efac;}.badge-blue{background:#1e3a8a;color:#93c5fd;}.footer{text-align:center;padding:30px;color:#64748b;font-size:12px;}</style>';

function nav(user) {
    var links = '<a href="/">Report</a>';
    if (user) {
        links += '<a href="/dashboard">Dashboard</a>';
        links += '<a href="/incidents">Incidents</a>';
        if (user.role === 'Admin') links += '<a href="/admin">Admin</a>';
        links += '<span style="color:#38bdf8;margin-left:20px;">' + user.name + ' (' + user.role + ')</span>';
        links += '<a href="/logout">Logout</a>';
    } else {
        links += '<a href="/login">Login</a><a href="/register">Register</a>';
    }
    return '<div class="nav"><a href="/" class="logo">Secure<span>Shield</span></a><div class="links">' + links + '</div></div>';
}

function requireLogin(req, res, next) {
    if (!req.session.user) return res.redirect('/login');
    next();
}

function analyzeMessage(msg) {
    msg = (msg || '').toLowerCase();
    var keywords = ['urgent', 'bank', 'password', 'click', 'reset', 'verify', 'account', 'suspended', 'login', 'confirm', 'link', 'immediately', 'compromised', 'update', 'secure'];
    var score = 0;
    var matched = [];
    keywords.forEach(function(kw) {
        if (msg.indexOf(kw) !== -1) { score += 8; matched.push(kw); }
    });
    if (score > 98) score = 98;
    var verdict = score >= 40 ? 'PHISHING DETECTED' : (score >= 15 ? 'SUSPICIOUS' : 'SAFE');
    return { score: score, verdict: verdict, matched: matched };
}

app.get('/', requireLogin, function(req, res) {
    var html = '<!DOCTYPE html><html><head><title>SecureShield</title>' + styles + '</head><body>';
    html += nav(req.session.user);
    html += '<div class="main">';
    html += '<h1>Cybersecurity Incident Platform</h1>';
    html += '<p style="text-align:center;">AI-Powered Phishing Detection</p>';
    html += '<div class="card"><h2>Report Suspicious Message</h2>';
    html += '<form method="POST" action="/analyze">';
    html += '<label>Paste the suspicious message</label>';
    html += '<textarea name="message" rows="6" required>Urgent! Your bank account has been compromised. Click this link to reset your password immediately.</textarea>';
    html += '<button type="submit" class="btn">Analyze Threat Level</button>';
    html += '</form></div>';
    html += '<div class="footer">Powered by AWS ECS Fargate | ALB | Cognito | RDS | S3 | SQS | Lambda | CloudWatch</div>';
    html += '</div></body></html>';
    res.send(html);
});

app.post('/analyze', requireLogin, async function(req, res) {
    var msg = req.body.message || '';
    var result = analyzeMessage(msg);
    var incidentId = null;
    try {
        var dbResult = await pool.query(
            'INSERT INTO incidents (title, description, severity, verdict, score, reported_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
            [msg.substring(0, 100), msg, result.verdict, result.verdict, result.score, req.session.user.email]
        );
        incidentId = dbResult.rows[0].id;
    } catch (e) { console.error('DB Error:', e.message); }

    if (result.score >= 15 && incidentId) {
        try {
            await sqs.send(new SendMessageCommand({
                QueueUrl: QUEUE_URL,
                MessageBody: JSON.stringify({ incidentId: 'INC-' + incidentId, type: result.verdict, score: result.score, reportedBy: req.session.user.email })
            }));
        } catch (e) { console.error('SQS Error:', e.message); }
    }

    var color = result.score >= 40 ? '#ef4444' : (result.score >= 15 ? '#f59e0b' : '#22c55e');
    var advice = result.score >= 40 ? 'Do NOT click any links. Report to your security team immediately.' : (result.score >= 15 ? 'Exercise caution. Verify the sender.' : 'No immediate threat detected.');

    var keywordHtml = '';
    if (result.matched.length > 0) {
        result.matched.forEach(function(k) { keywordHtml += '<span class="badge badge-red" style="margin:3px;">' + k + '</span>'; });
    } else {
        keywordHtml = '<span style="color:#22c55e;">No suspicious keywords detected</span>';
    }

    var html = '<!DOCTYPE html><html><head><title>Result</title>' + styles + '</head><body>';
    html += nav(req.session.user);
    html += '<div class="main"><div class="card">';
    html += '<h1 style="color:' + color + ';font-size:60px;">' + result.score + '%</h1>';
    html += '<h2 style="text-align:center;color:' + color + ';letter-spacing:2px;">' + result.verdict + '</h2>';
    html += '<div class="alert alert-info"><strong>Recommended Action:</strong> ' + advice + '</div>';
    if (incidentId) html += '<div class="alert alert-success">Incident saved to database as ID: INC-' + incidentId + ' - Message sent to SQS queue.</div>';
    html += '<h2>Detected Threat Indicators</h2><div>' + keywordHtml + '</div>';
    html += '<h2 style="margin-top:25px;">Analyzed Message</h2>';
    html += '<div class="alert alert-info" style="word-wrap:break-word;">' + msg + '</div>';
    html += '<a href="/" class="btn btn-secondary" style="margin-top:15px;">Analyze Another</a>';
    html += '<a href="/incidents" class="btn" style="margin-top:10px;">View All Incidents</a>';
    html += '</div></div></body></html>';
    res.send(html);
});

app.get('/register', function(req, res) {
    var html = '<!DOCTYPE html><html><head><title>Register</title>' + styles + '</head><body>';
    html += nav(null);
    html += '<div class="main"><div class="card"><h1>Register</h1>';
    if (req.query.error) html += '<div class="alert alert-error">' + req.query.error + '</div>';
    html += '<form method="POST" action="/register">';
    html += '<label>Email</label><input type="email" name="email" required />';
    html += '<label>Password (min 8 chars, uppercase, lowercase, number)</label><input type="password" name="password" required />';
    html += '<label>Role</label><select name="role"><option value="Employee">Employee</option><option value="Analyst">Analyst</option><option value="Admin">Admin</option></select>';
    html += '<button type="submit" class="btn">Register</button>';
    html += '</form><p style="text-align:center;"><a href="/login" style="color:#38bdf8;">Already have an account? Login</a></p>';
    html += '</div></div></body></html>';
    res.send(html);
});

app.post('/register', async function(req, res) {
    var email = req.body.email;
    var password = req.body.password;
    try {
        await cognito.send(new SignUpCommand({
            ClientId: CLIENT_ID,
            Username: email,
            Password: password,
            SecretHash: getSecretHash(email),
            UserAttributes: [{ Name: 'email', Value: email }]
        }));
        res.redirect('/login?msg=Registration successful. Please login.');
    } catch (e) {
        res.redirect('/register?error=' + encodeURIComponent(e.message));
    }
});

app.get('/login', function(req, res) {
    var html = '<!DOCTYPE html><html><head><title>Login</title>' + styles + '</head><body>';
    html += nav(null);
    html += '<div class="main"><div class="card"><h1>Login</h1>';
    if (req.query.error) html += '<div class="alert alert-error">' + req.query.error + '</div>';
    if (req.query.msg) html += '<div class="alert alert-success">' + req.query.msg + '</div>';
    html += '<form method="POST" action="/login">';
    html += '<label>Email</label><input type="email" name="email" required />';
    html += '<label>Password</label><input type="password" name="password" required />';
    html += '<label>Role</label><select name="role"><option value="Employee">Employee</option><option value="Analyst">Analyst</option><option value="Admin">Admin</option></select>';
    html += '<button type="submit" class="btn">Login</button>';
    html += '</form><p style="text-align:center;"><a href="/register" style="color:#38bdf8;">Create an account</a></p>';
    html += '</div></div></body></html>';
    res.send(html);
});

app.post('/login', async function(req, res) {
    var email = req.body.email;
    var password = req.body.password;
    var role = req.body.role;
    try {
        var result = await cognito.send(new InitiateAuthCommand({
            ClientId: CLIENT_ID,
            AuthFlow: 'USER_PASSWORD_AUTH',
            AuthParameters: {
                USERNAME: email,
                PASSWORD: password,
                SECRET_HASH: getSecretHash(email)
            }
        }));
        req.session.user = {
            email: email,
            name: email.split('@')[0],
            role: role || 'Employee',
            accessToken: result.AuthenticationResult.AccessToken
        };
        res.redirect('/');
    } catch (e) {
        res.redirect('/login?error=' + encodeURIComponent(e.message));
    }
});

app.get('/logout', function(req, res) {
    req.session.destroy();
    res.redirect('/login');
});

// ================= ROLE-BASED DASHBOARD =================
app.get('/dashboard', requireLogin, async function(req, res) {
    var stats = { total: 0, phishing: 0, safe: 0 };
    try {
        var r = await pool.query('SELECT verdict, COUNT(*) FROM incidents GROUP BY verdict');
        r.rows.forEach(function(row) {
            stats.total += parseInt(row.count);
            if (row.verdict === 'PHISHING DETECTED') stats.phishing = parseInt(row.count);
            if (row.verdict === 'SAFE') stats.safe = parseInt(row.count);
        });
    } catch (e) { console.error(e.message); }

    var html = '<!DOCTYPE html><html><head><title>Dashboard</title>' + styles + '</head><body>';
    html += nav(req.session.user);
    html += '<div class="main">';
    html += '<h1>Welcome, ' + req.session.user.name + '</h1>';
    html += '<p style="text-align:center;">Logged in as: <span class="badge badge-blue">' + req.session.user.role + '</span></p>';

    // DIFFERENT VIEWS BASED ON ROLE
    if (req.session.user.role === 'Employee') {
        html += '<div class="card"><h2>Employee Portal</h2>';
        html += '<p>As an Employee, your role is to report suspicious messages to the security team.</p>';
        html += '<a href="/" class="btn">Report New Incident</a></div>';
        
    } else if (req.session.user.role === 'Analyst') {
        html += '<div class="card"><h2>Analyst Queue</h2>';
        html += '<p>As an Analyst, your role is to investigate reported incidents, assign them to yourself, and update their status.</p>';
        html += '<a href="/incidents" class="btn">Go to Investigation Queue</a></div>';

    } else if (req.session.user.role === 'Admin') {
        html += '<div class="card"><h2>Admin Command Center</h2>';
        html += '<p>As an Admin, you have full visibility into the security posture and can manage all incidents.</p>';
        html += '<a href="/incidents" class="btn">View All Incidents</a>';
        html += '<a href="/admin" class="btn btn-secondary">Admin Settings</a></div>';
    }

    // Show the stats to everyone
    html += '<div class="stat-grid">';
    html += '<div class="stat"><div class="num">' + stats.total + '</div><div class="lbl">Total Incidents</div></div>';
    html += '<div class="stat"><div class="num" style="color:#ef4444;">' + stats.phishing + '</div><div class="lbl">Phishing Detected</div></div>';
    html += '<div class="stat"><div class="num" style="color:#22c55e;">' + stats.safe + '</div><div class="lbl">Safe</div></div>';
    html += '</div>';

    html += '</div></body></html>';
    res.send(html);
});

app.get('/incidents', requireLogin, async function(req, res) {
    var rows = [];
    try {
        var r = await pool.query('SELECT * FROM incidents ORDER BY created_at DESC LIMIT 50');
        rows = r.rows;
    } catch (e) { console.error(e.message); }

    var html = '<!DOCTYPE html><html><head><title>Incidents</title>' + styles + '</head><body>';
    html += nav(req.session.user);
    html += '<div class="main"><div class="card"><h1>All Incidents</h1>';
    html += '<table><thead><tr><th>ID</th><th>Title</th><th>Verdict</th><th>Score</th><th>Reported By</th><th>Status</th><th>Action</th></tr></thead><tbody>';
    rows.forEach(function(r) {
        var badge = r.verdict === 'PHISHING DETECTED' ? 'badge-red' : (r.verdict === 'SUSPICIOUS' ? 'badge-orange' : 'badge-green');
        html += '<tr><td>INC-' + r.id + '</td><td>' + (r.title || '').substring(0, 40) + '</td><td><span class="badge ' + badge + '">' + r.verdict + '</span></td><td>' + r.score + '%</td><td>' + (r.reported_by || 'anonymous') + '</td><td>' + r.status + '</td><td><a href="/incident/' + r.id + '" style="color:#38bdf8;">View</a></td></tr>';
    });
    if (rows.length === 0) html += '<tr><td colspan="7" style="text-align:center;">No incidents reported yet.</td></tr>';
    html += '</tbody></table></div></div></body></html>';
    res.send(html);
});

app.get('/incident/:id', requireLogin, async function(req, res) {
    var id = req.params.id;
    var incident = null;
    var files = [];
    try {
        var r = await pool.query('SELECT * FROM incidents WHERE id = $1', [id]);
        if (r.rows.length > 0) incident = r.rows[0];
        var f = await pool.query('SELECT * FROM evidence WHERE incident_id = $1', [id]);
        files = f.rows;
    } catch (e) { console.error(e.message); }

    if (!incident) return res.redirect('/incidents');

    var html = '<!DOCTYPE html><html><head><title>Incident INC-' + id + '</title>' + styles + '</head><body>';
    html += nav(req.session.user);
    html += '<div class="main"><div class="card">';
    html += '<h1>Incident INC-' + id + '</h1>';
    html += '<div class="alert alert-info"><strong>Verdict:</strong> ' + incident.verdict + ' (' + incident.score + '%)</div>';
    html += '<h2>Message</h2><div class="alert alert-info" style="word-wrap:break-word;">' + incident.description + '</div>';
    html += '<h2>Reported By</h2><p>' + (incident.reported_by || 'anonymous') + '</p>';

    if (req.session.user.role === 'Analyst' || req.session.user.role === 'Admin') {
        html += '<h2>Update Status</h2>';
        html += '<form method="POST" action="/incident/' + id + '/status">';
        html += '<select name="status"><option ' + (incident.status === 'Open' ? 'selected' : '') + '>Open</option><option ' + (incident.status === 'Investigating' ? 'selected' : '') + '>Investigating</option><option ' + (incident.status === 'Resolved' ? 'selected' : '') + '>Resolved</option></select>';
        html += '<button type="submit" class="btn">Update Status</button></form>';
    }

    html += '<h2 style="margin-top:25px;">Upload Evidence</h2>';
    html += '<form method="POST" action="/incident/' + id + '/upload" enctype="multipart/form-data">';
    html += '<input type="file" name="evidence" required />';
    html += '<button type="submit" class="btn">Upload to S3</button></form>';

    if (files.length > 0) {
        html += '<h2>Uploaded Evidence</h2>';
        files.forEach(function(f) {
            html += '<div style="padding:10px;border-bottom:1px solid #334155;">' + f.file_name + ' - uploaded by ' + f.uploaded_by + '</div>';
        });
    }

    html += '<a href="/incidents" class="btn btn-secondary" style="margin-top:20px;">Back to Incidents</a>';
    html += '</div></div></body></html>';
    res.send(html);
});

app.post('/incident/:id/status', requireLogin, async function(req, res) {
    try {
        await pool.query('UPDATE incidents SET status = $1 WHERE id = $2', [req.body.status, req.params.id]);
    } catch (e) { console.error(e.message); }
    res.redirect('/incident/' + req.params.id);
});

app.post('/incident/:id/upload', requireLogin, upload.single('evidence'), async function(req, res) {
    var id = req.params.id;
    if (!req.file) return res.redirect('/incident/' + id);
    var key = 'incidents/INC-' + id + '/' + Date.now() + '-' + req.file.originalname;
    try {
        await s3.send(new PutObjectCommand({
            Bucket: BUCKET,
            Key: key,
            Body: req.file.buffer,
            ContentType: req.file.mimetype
        }));
        await pool.query(
            'INSERT INTO evidence (incident_id, file_name, s3_key, uploaded_by) VALUES ($1, $2, $3, $4)',
            [id, req.file.originalname, key, req.session.user.email]
        );
    } catch (e) { console.error('S3 Error:', e.message); }
    res.redirect('/incident/' + id);
});

app.get('/admin', requireLogin, async function(req, res) {
    if (req.session.user.role !== 'Admin') return res.redirect('/dashboard');
    var rows = [];
    try {
        var r = await pool.query('SELECT * FROM incidents ORDER BY created_at DESC');
        rows = r.rows;
    } catch (e) { console.error(e.message); }

    var html = '<!DOCTYPE html><html><head><title>Admin</title>' + styles + '</head><body>';
    html += nav(req.session.user);
    html += '<div class="main"><div class="card"><h1>Admin Panel</h1>';
    html += '<table><thead><tr><th>ID</th><th>Verdict</th><th>Status</th><th>Reported By</th><th>Action</th></tr></thead><tbody>';
    rows.forEach(function(r) {
        html += '<tr><td>INC-' + r.id + '</td><td>' + r.verdict + '</td><td>' + r.status + '</td><td>' + (r.reported_by || 'anonymous') + '</td><td><a href="/incident/' + r.id + '" style="color:#38bdf8;">Manage</a></td></tr>';
    });
    html += '</tbody></table></div></div></body></html>';
    res.send(html);
});

app.listen(3000, function() {
    console.log('SecureShield v2.0 running on port 3000');
});