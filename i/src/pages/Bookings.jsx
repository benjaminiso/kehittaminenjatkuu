export default function Bookings() {
  return (
    <section style={{ maxWidth: "600px", margin: "auto" }}>
      <h2>Bike Booking</h2>

      <form style={{ display: "grid", gap: "12px" }}>
        <input placeholder="Full name" />
        <input placeholder="Email" type="email" />

        <select>
          <option>City Cruiser</option>
          <option>Trail Explorer</option>
          <option>Road Runner</option>
        </select>

        <input type="date" />
        <input type="date" />

        <label>
          <input type="checkbox" /> Accept terms
        </label>

        <button type="submit">Book now</button>
      </form>
    </section>
  );
}