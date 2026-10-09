# Naruto RPG — GitHub Pages + Render

1. Deploy the backend on Render using `render.yaml`.
2. Set `FRONTEND_URL` to your GitHub Pages URL, e.g. `https://USERNAME.github.io/REPOSITORY`.
3. Copy your Render service URL into `index.html`:
   `const RENDER_URL = 'https://YOUR-RENDER-SERVICE.onrender.com';`
4. Push `index.html` to GitHub Pages.
5. Test `https://YOUR-RENDER-SERVICE.onrender.com/api/health`.

Render hosts Node.js + Socket.IO + PostgreSQL. GitHub Pages hosts only the frontend.
