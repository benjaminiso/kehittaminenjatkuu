import Productcard from "../components/Productcard";

export default function Catalog() {
  return (
    <div>
      {/* Intro */}
      <section id="intro">
        <h2>Rental catalog</h2>
        <p style={{ color: "var(--muted)", maxWidth: "70ch" }}>
          Our selection includes city cruisers, trail bikes, road bikes and more.
          Helmets and locks included with every rental.
        </p>
      </section>

      {/* Products */}
      <section id="catalog" style={{ marginTop: "20px" }}>
        <div className="product-grid">

          <Productcard
            image="/Pictures/citybike.jpg"
            title="City Cruiser"
            text="Comfortable upright bike for city rides."
            price="39 €/d"
          />

          <Productcard
            image="/Pictures/mountainbike.jpg"
            title="Trail Explorer"
            text="Strong bike for off-road and gravel paths."
            price="49 €/d"
          />

          <Productcard
            image="/Pictures/roadbike.webp"
            title="Road Runner"
            text="Lightweight bike for speed and long rides."
            price="59 €/d"
          />

          <Productcard
            image="/Pictures/commuterbike.jpg"
            title="Electric Commuter"
            text="Assisted riding for easy commuting."
            price="89 €/d"
          />

          <Productcard
            image="/Pictures/childbike.jpg"
            title="Kids Ride"
            text="Safe and stable bike for children."
            price="19 €/d"
          />

          <Productcard
            image="/Pictures/gravelbike.webp"
            title="Gravel Adventure"
            text="Perfect for mixed terrain and long trips."
            price="52 €/d"
          />

        </div>
      </section>

      {/* Video */}
      <section id="video" style={{ marginTop: "30px" }}>
        <h2>Safety video</h2>
        <p style={{ color: "var(--muted)" }}>
          Learn how to ride safely and properly use a helmet.
        </p>

        <div style={{ marginTop: "12px" }}>
          <iframe
            width="100%"
            height="400"
            style={{ borderRadius: "12px", border: 0 }}
            src="https://www.youtube.com/embed/1XJIqbbL1uc"
            title="Safety Video"
            allowFullScreen
          />
        </div>
      </section>
    </div>
  );
}