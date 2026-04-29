export default function Navbar({ setPage }) {
  return (
    <header>
      <div className="brand">
        <div className="logo">
          <svg viewBox="0 0 24 24">
            <path d="M5 16l3-8h2l-3 8h6l3-8h2l-3 8h2v2H5v-2z" />
          </svg>
        </div>

        <div>
          <h1 className="brand-title">Voltbikesuper</h1>
          <p className="brand-sub">Bikes for city days & weekend escapes</p>
        </div>
      </div>

      <nav>
        <ul>
          <li><button onClick={() => setPage?.("home")}>Home</button></li>
          <li><button onClick={() => setPage?.("catalog")}>Catalog</button></li>
          <li><button onClick={() => setPage?.("bookings")}>Bookings</button></li>
        </ul>
      </nav>
    </header>
  );
}