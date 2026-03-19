# E-Commerce Checkout

A Node.js e-commerce checkout service. Handles shopping cart management, price calculation, payment processing, and order confirmation.

## Features

- Shopping cart with add/remove/update
- Discount code validation
- Payment gateway integration (Stripe)
- Order confirmation emails
- Inventory management

## API

- POST /cart/add - Add item to cart
- POST /checkout - Process payment
- GET /order/:id - Get order status
- POST /discount/validate - Validate discount code
