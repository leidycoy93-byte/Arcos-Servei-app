require('dotenv').config({ quiet: true });
const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { db, uuidv4 } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'cambia-este-secreto-en-produccion',
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 12, // 12 horas
      httpOnly: true
    }
  })
);
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Helpers ----------
function publicUser(u) {
  if (!u) return null;
  const { passwordHash, ...rest } = u;
  return rest;
}

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'No autenticado' });
  const user = db.get('users').find({ id: req.session.userId }).value();
  if (!user || !user.active) return res.status(401).json({ error: 'No autenticado' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Solo administradores' });
  next();
}

function hoursBetween(startIso, endIso) {
  const start = new Date(startIso).getTime();
  const end = new Date(endIso).getTime();
  return Math.max(0, (end - start) / (1000 * 60 * 60));
}

// ---------- Auth ----------
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = db.get('users').find({ username }).value();
  if (!user || !user.active || !bcrypt.compareSync(password || '', user.passwordHash)) {
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }
  req.session.userId = user.id;
  res.json({ user: publicUser(user) });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

// ---------- Empleados (admin) ----------
app.get('/api/employees', requireAuth, requireAdmin, (req, res) => {
  res.json(db.get('users').map(publicUser).value());
});

app.post('/api/employees', requireAuth, requireAdmin, (req, res) => {
  const { username, password, name, role } = req.body || {};
  if (!username || !password || !name) {
    return res.status(400).json({ error: 'Usuario, contraseña y nombre son obligatorios' });
  }
  if (db.get('users').find({ username }).value()) {
    return res.status(400).json({ error: 'Ese usuario ya existe' });
  }
  const newUser = {
    id: uuidv4(),
    username,
    passwordHash: bcrypt.hashSync(password, 8),
    role: role === 'admin' ? 'admin' : 'employee',
    name,
    active: true,
    createdAt: new Date().toISOString()
  };
  db.get('users').push(newUser).write();
  res.status(201).json(publicUser(newUser));
});

app.put('/api/employees/:id', requireAuth, requireAdmin, (req, res) => {
  const { name, role, active, password } = req.body || {};
  const entry = db.get('users').find({ id: req.params.id });
  if (!entry.value()) return res.status(404).json({ error: 'No encontrado' });
  const updates = {};
  if (name !== undefined) updates.name = name;
  if (role !== undefined) updates.role = role === 'admin' ? 'admin' : 'employee';
  if (active !== undefined) updates.active = !!active;
  if (password) updates.passwordHash = bcrypt.hashSync(password, 8);
  entry.assign(updates).write();
  res.json(publicUser(entry.value()));
});

app.delete('/api/employees/:id', requireAuth, requireAdmin, (req, res) => {
  const entry = db.get('users').find({ id: req.params.id });
  if (!entry.value()) return res.status(404).json({ error: 'No encontrado' });
  entry.assign({ active: false }).write();
  res.json({ ok: true });
});

// ---------- Clientes ----------
app.get('/api/clients', requireAuth, (req, res) => {
  let list = db.get('clients');
  if (req.user.role !== 'admin') list = list.filter({ active: true });
  res.json(list.value());
});

app.post('/api/clients', requireAuth, requireAdmin, (req, res) => {
  const { name, address, contact, notes } = req.body || {};
  if (!name) return res.status(400).json({ error: 'El nombre del cliente es obligatorio' });
  const newClient = {
    id: uuidv4(),
    name,
    address: address || '',
    contact: contact || '',
    notes: notes || '',
    active: true
  };
  db.get('clients').push(newClient).write();
  res.status(201).json(newClient);
});

app.put('/api/clients/:id', requireAuth, requireAdmin, (req, res) => {
  const entry = db.get('clients').find({ id: req.params.id });
  if (!entry.value()) return res.status(404).json({ error: 'No encontrado' });
  const { name, address, contact, notes, active } = req.body || {};
  const updates = {};
  if (name !== undefined) updates.name = name;
  if (address !== undefined) updates.address = address;
  if (contact !== undefined) updates.contact = contact;
  if (notes !== undefined) updates.notes = notes;
  if (active !== undefined) updates.active = !!active;
  entry.assign(updates).write();
  res.json(entry.value());
});

app.delete('/api/clients/:id', requireAuth, requireAdmin, (req, res) => {
  const entry = db.get('clients').find({ id: req.params.id });
  if (!entry.value()) return res.status(404).json({ error: 'No encontrado' });
  entry.assign({ active: false }).write();
  res.json({ ok: true });
});

// ---------- Servicios ----------
app.get('/api/services', requireAuth, (req, res) => {
  let list = db.get('services');
  if (req.user.role !== 'admin') list = list.filter({ active: true });
  res.json(list.value());
});

app.post('/api/services', requireAuth, requireAdmin, (req, res) => {
  const { name, hourlyRate } = req.body || {};
  if (!name) return res.status(400).json({ error: 'El nombre del servicio es obligatorio' });
  const newService = {
    id: uuidv4(),
    name,
    hourlyRate: hourlyRate != null && hourlyRate !== '' ? Number(hourlyRate) : null,
    active: true
  };
  db.get('services').push(newService).write();
  res.status(201).json(newService);
});

app.put('/api/services/:id', requireAuth, requireAdmin, (req, res) => {
  const entry = db.get('services').find({ id: req.params.id });
  if (!entry.value()) return res.status(404).json({ error: 'No encontrado' });
  const { name, hourlyRate, active } = req.body || {};
  const updates = {};
  if (name !== undefined) updates.name = name;
  if (hourlyRate !== undefined)
    updates.hourlyRate = hourlyRate != null && hourlyRate !== '' ? Number(hourlyRate) : null;
  if (active !== undefined) updates.active = !!active;
  entry.assign(updates).write();
  res.json(entry.value());
});

app.delete('/api/services/:id', requireAuth, requireAdmin, (req, res) => {
  const entry = db.get('services').find({ id: req.params.id });
  if (!entry.value()) return res.status(404).json({ error: 'No encontrado' });
  entry.assign({ active: false }).write();
  res.json({ ok: true });
});

// ---------- Registro de horas ----------
function enrichEntry(e) {
  const client = db.get('clients').find({ id: e.clientId }).value();
  const service = db.get('services').find({ id: e.serviceId }).value();
  const employee = db.get('users').find({ id: e.userId }).value();
  return {
    ...e,
    clientName: client ? client.name : '(cliente eliminado)',
    serviceName: service ? service.name : '(servicio eliminado)',
    employeeName: employee ? employee.name : '(empleado eliminado)',
    hours: e.endTime ? hoursBetween(e.startTime, e.endTime) : null
  };
}

app.get('/api/time-entries/current', requireAuth, (req, res) => {
  const open = db
    .get('timeEntries')
    .find({ userId: req.user.id, status: 'open' })
    .value();
  res.json(open ? enrichEntry(open) : null);
});

app.post('/api/time-entries/clock-in', requireAuth, (req, res) => {
  const { clientId, serviceId, lat, lng, notes } = req.body || {};
  if (!clientId || !serviceId) {
    return res.status(400).json({ error: 'Selecciona cliente y servicio' });
  }
  const alreadyOpen = db
    .get('timeEntries')
    .find({ userId: req.user.id, status: 'open' })
    .value();
  if (alreadyOpen) {
    return res.status(400).json({ error: 'Ya tienes una jornada abierta. Marca salida primero.' });
  }
  const entry = {
    id: uuidv4(),
    userId: req.user.id,
    clientId,
    serviceId,
    startTime: new Date().toISOString(),
    startLat: lat != null ? Number(lat) : null,
    startLng: lng != null ? Number(lng) : null,
    endTime: null,
    endLat: null,
    endLng: null,
    notes: notes || '',
    status: 'open'
  };
  db.get('timeEntries').push(entry).write();
  res.status(201).json(enrichEntry(entry));
});

app.post('/api/time-entries/:id/clock-out', requireAuth, (req, res) => {
  const entryRef = db.get('timeEntries').find({ id: req.params.id, userId: req.user.id });
  const entry = entryRef.value();
  if (!entry) return res.status(404).json({ error: 'Registro no encontrado' });
  if (entry.status !== 'open') return res.status(400).json({ error: 'Este registro ya está cerrado' });
  const { lat, lng, notes } = req.body || {};
  entryRef
    .assign({
      endTime: new Date().toISOString(),
      endLat: lat != null ? Number(lat) : null,
      endLng: lng != null ? Number(lng) : null,
      notes: notes ? (entry.notes ? entry.notes + ' | ' + notes : notes) : entry.notes,
      status: 'closed'
    })
    .write();
  res.json(enrichEntry(entryRef.value()));
});

app.get('/api/time-entries/mine', requireAuth, (req, res) => {
  const list = db
    .get('timeEntries')
    .filter({ userId: req.user.id })
    .orderBy(['startTime'], ['desc'])
    .value()
    .map(enrichEntry);
  res.json(list);
});

app.get('/api/time-entries', requireAuth, requireAdmin, (req, res) => {
  const { employeeId, clientId, serviceId, from, to, status } = req.query;
  let list = db.get('timeEntries').value();
  if (employeeId) list = list.filter((e) => e.userId === employeeId);
  if (clientId) list = list.filter((e) => e.clientId === clientId);
  if (serviceId) list = list.filter((e) => e.serviceId === serviceId);
  if (status) list = list.filter((e) => e.status === status);
  if (from) list = list.filter((e) => new Date(e.startTime) >= new Date(from));
  if (to) list = list.filter((e) => new Date(e.startTime) <= new Date(to + 'T23:59:59'));
  list = list.sort((a, b) => new Date(b.startTime) - new Date(a.startTime));
  res.json(list.map(enrichEntry));
});

// ---------- Resumen de horas ----------
function buildSummary(req) {
  const { employeeId, clientId, serviceId, from, to } = req.query;
  let list = db.get('timeEntries').value();
  if (employeeId) list = list.filter((e) => e.userId === employeeId);
  if (clientId) list = list.filter((e) => e.clientId === clientId);
  if (serviceId) list = list.filter((e) => e.serviceId === serviceId);
  if (from) list = list.filter((e) => new Date(e.startTime) >= new Date(from));
  if (to) list = list.filter((e) => new Date(e.startTime) <= new Date(to + 'T23:59:59'));
  list = list.filter((e) => e.status === 'closed');

  const users = db.get('users').value();
  const clients = db.get('clients').value();
  const services = db.get('services').value();
  const nameOf = (arr, id) => (arr.find((x) => x.id === id) || {}).name || '(eliminado)';

  const byEmployee = {};
  const byClient = {};
  const byService = {};
  const byEmployeeClientService = {};
  let totalHours = 0;

  list.forEach((e) => {
    const h = hoursBetween(e.startTime, e.endTime);
    totalHours += h;

    const empName = nameOf(users, e.userId);
    byEmployee[empName] = (byEmployee[empName] || 0) + h;

    const cliName = nameOf(clients, e.clientId);
    byClient[cliName] = (byClient[cliName] || 0) + h;

    const svcName = nameOf(services, e.serviceId);
    byService[svcName] = (byService[svcName] || 0) + h;

    const key = `${empName}|||${cliName}|||${svcName}`;
    byEmployeeClientService[key] = (byEmployeeClientService[key] || 0) + h;
  });

  const detail = Object.entries(byEmployeeClientService).map(([key, hours]) => {
    const [employee, client, service] = key.split('|||');
    return { employee, client, service, hours: Math.round(hours * 100) / 100 };
  });

  const round = (obj) =>
    Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, Math.round(v * 100) / 100]));

  return {
    totalHours: Math.round(totalHours * 100) / 100,
    entryCount: list.length,
    byEmployee: round(byEmployee),
    byClient: round(byClient),
    byService: round(byService),
    detail
  };
}

app.get('/api/summary', requireAuth, requireAdmin, (req, res) => {
  res.json(buildSummary(req));
});

app.get('/api/summary/export.csv', requireAuth, requireAdmin, (req, res) => {
  const summary = buildSummary(req);
  let csv = 'Empleado,Cliente,Servicio,Horas\n';
  summary.detail.forEach((row) => {
    csv += `"${row.employee}","${row.client}","${row.service}",${row.hours}\n`;
  });
  csv += `\nTotal horas,,,${summary.totalHours}\n`;
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="resumen-horas.csv"');
  res.send(csv);
});

// Fallback: servir index.html para rutas de la SPA
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
