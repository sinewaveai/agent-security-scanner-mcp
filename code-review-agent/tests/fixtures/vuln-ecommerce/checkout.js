const express = require('express');
const app = express();

app.use(express.json());

const carts = {};

// Add to cart - prototype pollution via merge
app.post('/cart/add', (req, res) => {
  const { userId, item } = req.body;
  if (!carts[userId]) carts[userId] = { items: [] };
  // Deep merge without prototype pollution protection
  merge(carts[userId], item);
  res.json(carts[userId]);
});

function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Apply discount - no auth check, price manipulation
app.post('/discount/validate', (req, res) => {
  const { code, cartTotal } = req.body;
  // User controls the cart total - should be server-side calculation
  const discounts = { SAVE10: 0.1, SAVE50: 0.5, EMPLOYEE: 1.0 };
  const discount = discounts[code];
  if (discount) {
    res.json({ newTotal: cartTotal * (1 - discount), valid: true });
  } else {
    res.json({ valid: false });
  }
});

// Checkout - open redirect in success URL
app.post('/checkout', (req, res) => {
  const { successUrl } = req.body;
  // Process payment...
  // Open redirect - user controls redirect destination
  res.redirect(successUrl);
});

// Order lookup - no authorization, IDOR
app.get('/order/:id', (req, res) => {
  // No check that requesting user owns this order
  const order = getOrder(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  res.json(order);
});

function getOrder(id) {
  // Stub
  return { id, items: [], total: 0, status: 'completed' };
}

app.listen(3000);
