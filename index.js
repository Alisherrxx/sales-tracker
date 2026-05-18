require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Нет токена' });
  const token = header.replace('Bearer ', '');
  try {
    req.agent = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Токен недействителен' });
  }
}

function adminAuth(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (key !== process.env.ADMIN_KEY) {
    return res.status(403).json({ error: 'Нет доступа' });
  }
  next();
}

app.post('/auth/login', async (req, res) => {
  const { login, password } = req.body;
  if (!login || !password) return res.status(400).json({ error: 'Укажи логин и пароль' });
  try {
    const result = await db.query(
      `SELECT a.*, d.name AS department_name FROM agents a JOIN departments d ON d.id = a.department_id WHERE LOWER(a.login) = LOWER($1) AND a.is_active = TRUE`,
      [login]
    );
    const agent = result.rows[0];
    if (!agent) return res.status(401).json({ error: 'Неверный логин или пароль' });
    const ok = await bcrypt.compare(password, agent.password_hash);
    if (!ok) return res.status(401).json({ error: 'Неверный логин или пароль' });
    const token = jwt.sign(
      { id: agent.id, name: agent.full_name, department_id: agent.department_id },
      process.env.JWT_SECRET,
      { expiresIn: '12h' }
    );
    res.json({ token, agent: { id: agent.id, full_name: agent.full_name, department_name: agent.department_name } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/location', auth, async (req, res) => {
  const { latitude, longitude, accuracy } = req.body;
  if (!latitude || !longitude) return res.status(400).json({ error: 'Нужны latitude и longitude' });
  try {
    await db.query(
      `INSERT INTO locations (agent_id, latitude, longitude, accuracy) VALUES ($1, $2, $3, $4)`,
      [req.agent.id, latitude, longitude, accuracy || null]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сохранения координат' });
  }
});

app.get('/agents/live', adminAuth, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT DISTINCT ON (a.id) a.id, a.full_name, a.phone, d.name AS department,
        l.latitude, l.longitude, l.recorded_at AS last_seen,
        EXTRACT(EPOCH FROM (NOW() - l.recorded_at)) / 60 AS minutes_ago
      FROM agents a
      JOIN departments d ON d.id = a.department_id
      LEFT JOIN locations l ON l.agent_id = a.id
      WHERE a.is_active = TRUE
      ORDER BY a.id, l.recorded_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка' });
  }
});

app.get('/agent/:id/route-today', adminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await db.query(
      `SELECT latitude, longitude, recorded_at FROM locations WHERE agent_id = $1 AND recorded_at >= CURRENT_DATE AND recorded_at < CURRENT_DATE + INTERVAL '1 day' ORDER BY recorded_at ASC`,
      [id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка' });
  }
});

app.post('/visit', auth, async (req, res) => {
  const { outlet_id, route_stop_id, latitude, longitude, result, note } = req.body;
  if (!outlet_id) return res.status(400).json({ error: 'Нужен outlet_id' });
  try {
    const visitResult = await db.query(
      `INSERT INTO visits (agent_id, outlet_id, route_stop_id, latitude, longitude, result, note) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [req.agent.id, outlet_id, route_stop_id || null, latitude || null, longitude || null, result || 'visited', note || null]
    );
    const visitId = visitResult.rows[0].id;
    if (route_stop_id) {
      await db.query(`UPDATE route_stops SET status = 'visited' WHERE id = $1`, [route_stop_id]);
    }
    res.json({ ok: true, visit_id: visitId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сохранения визита' });
  }
});

app.post('/sale', auth, async (req, res) => {
  const { visit_id, product_name, quantity, amount } = req.body;
  if (!visit_id || !product_name || !amount) return res.status(400).json({ error: 'Нужны visit_id, product_name, amount' });
  try {
    const check = await db.query(`SELECT id FROM visits WHERE id = $1 AND agent_id = $2`, [visit_id, req.agent.id]);
    if (!check.rows.length) return res.status(403).json({ error: 'Визит не найден' });
    await db.query(`INSERT INTO sales (visit_id, product_name, quantity, amount) VALUES ($1, $2, $3, $4)`, [visit_id, product_name, quantity || 1, amount]);
    await db.query(`UPDATE visits SET result = 'sold' WHERE id = $1`, [visit_id]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка' });
  }
});

app.get('/my-route', auth, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT rs.id AS stop_id, rs.planned_order, rs.status AS stop_status,
        o.id AS outlet_id, o.name AS outlet_name, o.address, o.latitude, o.longitude, o.category,
        v.id AS visit_id, v.result AS visit_result, v.visited_at
      FROM routes r
      JOIN route_stops rs ON rs.route_id = r.id
      JOIN outlets o ON o.id = rs.outlet_id
      LEFT JOIN visits v ON v.route_stop_id = rs.id
      WHERE r.agent_id = $1 AND r.route_date = CURRENT_DATE
      ORDER BY rs.planned_order
    `, [req.agent.id]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка' });
  }
});

app.get('/stats/today', adminAuth, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT a.id, a.full_name, d.name AS department,
        COUNT(DISTINCT v.id) AS total_visits,
        COUNT(DISTINCT s.id) AS total_sales,
        COALESCE(SUM(s.amount), 0) AS total_amount,
        MAX(l.recorded_at) AS last_seen
      FROM agents a
      JOIN departments d ON d.id = a.department_id
      LEFT JOIN visits v ON v.agent_id = a.id AND v.visited_at >= CURRENT_DATE
      LEFT JOIN sales s ON s.visit_id = v.id
      LEFT JOIN locations l ON l.agent_id = a.id
      WHERE a.is_active = TRUE
      GROUP BY a.id, a.full_name, d.name
      ORDER BY total_visits DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка' });
  }
});

app.get('/visits/today', adminAuth, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT v.id, v.visited_at, v.result, v.note,
        a.full_name AS agent_name, o.name AS outlet_name, o.address,
        COALESCE(SUM(s.amount), 0) AS total_amount
      FROM visits v
      JOIN agents a ON a.id = v.agent_id
      JOIN outlets o ON o.id = v.outlet_id
      LEFT JOIN sales s ON s.visit_id = v.id
      WHERE v.visited_at >= CURRENT_DATE
      GROUP BY v.id, v.visited_at, v.result, v.note, a.full_name, o.name, o.address
      ORDER BY v.visited_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка' });
  }
});

app.get('/agent/:id/activity', adminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const visits = await db.query(`
      SELECT v.visited_at, v.result, o.name AS outlet_name
      FROM visits v JOIN outlets o ON o.id = v.outlet_id
      WHERE v.agent_id = $1 AND v.visited_at >= CURRENT_DATE
      ORDER BY v.visited_at ASC
    `, [id]);
    const locations = await db.query(`
      SELECT MIN(recorded_at) AS first_seen, MAX(recorded_at) AS last_seen, COUNT(*) AS points
      FROM locations WHERE agent_id = $1 AND recorded_at >= CURRENT_DATE
    `, [id]);
    res.json({ visits: visits.rows, locations: locations.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка' });
  }
});

app.get('/agents', adminAuth, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT a.id, a.full_name, a.phone, a.login, a.is_active, d.name AS department
      FROM agents a JOIN departments d ON d.id = a.department_id
      ORDER BY a.full_name
    `);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Ошибка' }); }
});

app.get('/departments', adminAuth, async (req, res) => {
  try {
    const result = await db.query(`SELECT id, name FROM departments ORDER BY name`);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Ошибка' }); }
});

app.post('/agents', adminAuth, async (req, res) => {
  const { full_name, phone, login, password, department_id } = req.body;
  if (!full_name || !login || !password || !department_id) return res.status(400).json({ error: 'Заполни все поля' });
  try {
    const hash = await bcrypt.hash(password, 10);
    await db.query(
      `INSERT INTO agents (full_name, phone, login, password_hash, department_id) VALUES ($1, $2, $3, $4, $5)`,
      [full_name, phone || '', login, hash, department_id]
    );
    res.json({ ok: true });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Такой логин уже существует' });
    res.status(500).json({ error: 'Ошибка' });
  }
});

app.delete('/agents/:id', adminAuth, async (req, res) => {
  try {
    await db.query(`UPDATE agents SET is_active = FALSE WHERE id = $1`, [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Ошибка' }); }
});

app.get('/outlets', adminAuth, async (req, res) => {
  try {
    const result = await db.query(`SELECT id, name, address, latitude, longitude, category, is_active FROM outlets ORDER BY name`);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Ошибка' }); }
});

app.post('/outlets', adminAuth, async (req, res) => {
  const { name, address, latitude, longitude, category } = req.body;
  if (!name) return res.status(400).json({ error: 'Укажи название точки' });
  try {
    await db.query(
      `INSERT INTO outlets (name, address, latitude, longitude, category) VALUES ($1, $2, $3, $4, $5)`,
      [name, address || '', latitude || null, longitude || null, category || '']
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Ошибка' }); }
});

app.delete('/outlets/:id', adminAuth, async (req, res) => {
  try {
    await db.query(`UPDATE outlets SET is_active = FALSE WHERE id = $1`, [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Ошибка' }); }
});

// Получить маршрут агента на дату
app.get('/routes', adminAuth, async (req, res) => {
  const { agent_id, date } = req.query;
  try {
    const result = await db.query(`
      SELECT r.id, r.route_date, r.status,
        rs.id AS stop_id, rs.planned_order, rs.status AS stop_status,
        o.id AS outlet_id, o.name AS outlet_name, o.address
      FROM routes r
      JOIN route_stops rs ON rs.route_id = r.id
      JOIN outlets o ON o.id = rs.outlet_id
      WHERE r.agent_id = $1 AND r.route_date = $2
      ORDER BY rs.planned_order
    `, [agent_id, date]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Ошибка' }); }
});

// Создать маршрут
app.post('/routes', adminAuth, async (req, res) => {
  const { agent_id, date, outlet_ids } = req.body;
  if (!agent_id || !date || !outlet_ids || !outlet_ids.length) {
    return res.status(400).json({ error: 'Укажи агента, дату и точки' });
  }
  try {
    // Удаляем старый маршрут если есть
    const existing = await db.query(`SELECT id FROM routes WHERE agent_id = $1 AND route_date = $2`, [agent_id, date]);
    if (existing.rows.length) {
      await db.query(`DELETE FROM route_stops WHERE route_id = $1`, [existing.rows[0].id]);
      await db.query(`DELETE FROM routes WHERE id = $1`, [existing.rows[0].id]);
    }
    // Создаём новый маршрут
    const route = await db.query(
      `INSERT INTO routes (agent_id, route_date, status) VALUES ($1, $2, 'planned') RETURNING id`,
      [agent_id, date]
    );
    const routeId = route.rows[0].id;
    // Добавляем точки
    for (let i = 0; i < outlet_ids.length; i++) {
      await db.query(
        `INSERT INTO route_stops (route_id, outlet_id, planned_order) VALUES ($1, $2, $3)`,
        [routeId, outlet_ids[i], i + 1]
      );
    }
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка' });
  }
// Детальная информация по агенту за день
app.get('/agents/:id/detail', adminAuth, async (req, res) => {
  const { id } = req.params;
  const { date } = req.query;
  const targetDate = date || new Date().toISOString().split('T')[0];
  try {
    const agent = await db.query(`
      SELECT a.id, a.full_name, a.phone, d.name AS department
      FROM agents a JOIN departments d ON d.id = a.department_id
      WHERE a.id = $1
    `, [id]);

    const route = await db.query(`
      SELECT rs.id AS stop_id, rs.planned_order, rs.status AS stop_status,
        o.name AS outlet_name, o.address,
        v.id AS visit_id, v.result, v.note, v.visited_at, v.latitude, v.longitude
      FROM routes r
      JOIN route_stops rs ON rs.route_id = r.id
      JOIN outlets o ON o.id = rs.outlet_id
      LEFT JOIN visits v ON v.route_stop_id = rs.id
      WHERE r.agent_id = $1 AND r.route_date = $2
      ORDER BY rs.planned_order
    `, [id, targetDate]);

    const sales = await db.query(`
      SELECT s.product_name, s.quantity, s.amount, o.name AS outlet_name, v.visited_at
      FROM sales s
      JOIN visits v ON v.id = s.visit_id
      JOIN outlets o ON o.id = v.outlet_id
      WHERE v.agent_id = $1 AND v.visited_at >= $2::date AND v.visited_at < $2::date + INTERVAL '1 day'
      ORDER BY v.visited_at
    `, [id, targetDate]);

    const stats = await db.query(`
      SELECT COUNT(DISTINCT v.id) AS total_visits,
        COUNT(DISTINCT s.id) AS total_sales,
        COALESCE(SUM(s.amount), 0) AS total_amount
      FROM visits v
      LEFT JOIN sales s ON s.visit_id = v.id
      WHERE v.agent_id = $1 AND v.visited_at >= $2::date AND v.visited_at < $2::date + INTERVAL '1 day'
    `, [id, targetDate]);

    res.json({
      agent: agent.rows[0],
      route: route.rows,
      sales: sales.rows,
      stats: stats.rows[0]
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка' });
  }
});
 // Детальная информация по агенту за день
app.get('/agents/:id/detail', adminAuth, async (req, res) => {
  const { id } = req.params;
  const { date } = req.query;
  const targetDate = date || new Date().toISOString().split('T')[0];
  try {
    const agent = await db.query(`
      SELECT a.id, a.full_name, a.phone, d.name AS department
      FROM agents a JOIN departments d ON d.id = a.department_id
      WHERE a.id = $1
    `, [id]);

    const route = await db.query(`
      SELECT rs.id AS stop_id, rs.planned_order, rs.status AS stop_status,
        o.name AS outlet_name, o.address,
        v.id AS visit_id, v.result, v.note, v.visited_at, v.latitude, v.longitude
      FROM routes r
      JOIN route_stops rs ON rs.route_id = r.id
      JOIN outlets o ON o.id = rs.outlet_id
      LEFT JOIN visits v ON v.route_stop_id = rs.id
      WHERE r.agent_id = $1 AND r.route_date = $2
      ORDER BY rs.planned_order
    `, [id, targetDate]);

    const sales = await db.query(`
      SELECT s.product_name, s.quantity, s.amount, o.name AS outlet_name, v.visited_at
      FROM sales s
      JOIN visits v ON v.id = s.visit_id
      JOIN outlets o ON o.id = v.outlet_id
      WHERE v.agent_id = $1 AND v.visited_at >= $2::date AND v.visited_at < $2::date + INTERVAL '1 day'
      ORDER BY v.visited_at
    `, [id, targetDate]);

    const stats = await db.query(`
      SELECT COUNT(DISTINCT v.id) AS total_visits,
        COUNT(DISTINCT s.id) AS total_sales,
        COALESCE(SUM(s.amount), 0) AS total_amount
      FROM visits v
      LEFT JOIN sales s ON s.visit_id = v.id
      WHERE v.agent_id = $1 AND v.visited_at >= $2::date AND v.visited_at < $2::date + INTERVAL '1 day'
    `, [id, targetDate]);

    res.json({
      agent: agent.rows[0],
      route: route.rows,
      sales: sales.rows,
      stats: stats.rows[0]
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка' });
  }
}); }); app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
  console.log(`http://localhost:${PORT}`);
});