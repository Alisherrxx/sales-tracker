// index.js — главный файл сервера
require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const bcrypt   = require('bcrypt');
const jwt      = require('jsonwebtoken');
const db       = require('./db');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ============================================
// MIDDLEWARE: проверка JWT токена
// ============================================
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

// ============================================
// АВТОРИЗАЦИЯ
// ============================================

// POST /auth/login — вход агента
app.post('/auth/login', async (req, res) => {
  const { login, password } = req.body;
  if (!login || !password) {
    return res.status(400).json({ error: 'Укажи логин и пароль' });
  }

  try {
    const result = await db.query(
      `SELECT a.*, d.name AS department_name
       FROM agents a
       JOIN departments d ON d.id = a.department_id
       WHERE a.login = $1 AND a.is_active = TRUE`,
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

    res.json({
      token,
      agent: {
        id:              agent.id,
        full_name:       agent.full_name,
        department_name: agent.department_name,
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ============================================
// GPS — отправка координат (вызывается каждые 30–60 сек)
// ============================================

// POST /location — агент отправляет свою GPS-точку
app.post('/location', auth, async (req, res) => {
  const { latitude, longitude, accuracy } = req.body;

  if (!latitude || !longitude) {
    return res.status(400).json({ error: 'Нужны latitude и longitude' });
  }

  try {
    await db.query(
      `INSERT INTO locations (agent_id, latitude, longitude, accuracy)
       VALUES ($1, $2, $3, $4)`,
      [req.agent.id, latitude, longitude, accuracy || null]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сохранения координат' });
  }
});

// GET /agents/live — все агенты с последней GPS-точкой (для карты руководителя)
app.get('/agents/live', adminAuth, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT DISTINCT ON (a.id)
        a.id,
        a.full_name,
        a.phone,
        d.name AS department,
        l.latitude,
        l.longitude,
        l.recorded_at AS last_seen,
        -- сколько минут назад была последняя точка
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

// GET /agent/:id/route-today — маршрут агента за сегодня (GPS-трек)
app.get('/agent/:id/route-today', adminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await db.query(
      `SELECT latitude, longitude, recorded_at
       FROM locations
       WHERE agent_id = $1
         AND recorded_at >= CURRENT_DATE
         AND recorded_at < CURRENT_DATE + INTERVAL '1 day'
       ORDER BY recorded_at ASC`,
      [id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка' });
  }
});

// ============================================
// ВИЗИТЫ — фиксация посещения точки
// ============================================

// POST /visit — агент отмечает визит в торговую точку
app.post('/visit', auth, async (req, res) => {
  const { outlet_id, route_stop_id, latitude, longitude, result, note } = req.body;

  if (!outlet_id) {
    return res.status(400).json({ error: 'Нужен outlet_id' });
  }

  try {
    // Сохраняем визит
    const visitResult = await db.query(
      `INSERT INTO visits (agent_id, outlet_id, route_stop_id, latitude, longitude, result, note)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id`,
      [req.agent.id, outlet_id, route_stop_id || null, latitude || null, longitude || null, result || 'visited', note || null]
    );

    const visitId = visitResult.rows[0].id;

    // Обновляем статус остановки маршрута
    if (route_stop_id) {
      await db.query(
        `UPDATE route_stops SET status = 'visited' WHERE id = $1`,
        [route_stop_id]
      );
    }

    res.json({ ok: true, visit_id: visitId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка сохранения визита' });
  }
});

// POST /sale — агент фиксирует продажу
app.post('/sale', auth, async (req, res) => {
  const { visit_id, product_name, quantity, amount } = req.body;

  if (!visit_id || !product_name || !amount) {
    return res.status(400).json({ error: 'Нужны visit_id, product_name, amount' });
  }

  try {
    // Проверяем что визит принадлежит этому агенту
    const check = await db.query(
      `SELECT id FROM visits WHERE id = $1 AND agent_id = $2`,
      [visit_id, req.agent.id]
    );
    if (!check.rows.length) {
      return res.status(403).json({ error: 'Визит не найден' });
    }

    await db.query(
      `INSERT INTO sales (visit_id, product_name, quantity, amount)
       VALUES ($1, $2, $3, $4)`,
      [visit_id, product_name, quantity || 1, amount]
    );

    // Обновляем результат визита
    await db.query(
      `UPDATE visits SET result = 'sold' WHERE id = $1`,
      [visit_id]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка' });
  }
});

// ============================================
// МАРШРУТЫ — план на день
// ============================================

// GET /my-route — агент получает свой маршрут на сегодня
app.get('/my-route', auth, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT
        rs.id         AS stop_id,
        rs.planned_order,
        rs.status     AS stop_status,
        o.id          AS outlet_id,
        o.name        AS outlet_name,
        o.address,
        o.latitude,
        o.longitude,
        o.category,
        -- последний визит в эту точку сегодня
        v.id          AS visit_id,
        v.result      AS visit_result,
        v.visited_at
      FROM routes r
      JOIN route_stops rs ON rs.route_id = r.id
      JOIN outlets o ON o.id = rs.outlet_id
      LEFT JOIN visits v ON v.route_stop_id = rs.id
      WHERE r.agent_id = $1
        AND r.route_date = CURRENT_DATE
      ORDER BY rs.planned_order
    `, [req.agent.id]);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Ошибка' });
  }
});

// ============================================
// АНАЛИТИКА для руководителя
// ============================================

// GET /stats/today — сводка по всем агентам за сегодня
app.get('/stats/today', adminAuth, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT
        a.id,
        a.full_name,
        d.name AS department,
        COUNT(DISTINCT v.id)   AS total_visits,
        COUNT(DISTINCT s.id)   AS total_sales,
        COALESCE(SUM(s.amount), 0) AS total_amount,
        -- последняя GPS-точка
        MAX(l.recorded_at) AS last_seen
      FROM agents a
      JOIN departments d ON d.id = a.department_id
      LEFT JOIN visits v ON v.agent_id = a.id AND v.visited_at >= CURRENT_DATE
      LEFT JOIN sales  s ON s.visit_id = v.id
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

// ============================================
// Запуск сервера
// ============================================
// ВИЗИТЫ за сегодня для руководителя
app.get('/visits/today', adminAuth, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT
        v.id,
        v.visited_at,
        v.result,
        v.note,
        a.full_name AS agent_name,
        o.name AS outlet_name,
        o.address,
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
});app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на порту ${PORT}`);
  console.log(`   http://localhost:${PORT}`);
});
