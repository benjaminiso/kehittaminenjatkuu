export default function Navbar() {
  return (
    <nav style={{ display: "flex", gap: "20px", padding: "10px" }}>
      <h2>My Site</h2>

      <a href="#">Home</a>
      <a href="#">Catalog</a>
      <a href="#">Bookings</a>
    </nav>
  );
}