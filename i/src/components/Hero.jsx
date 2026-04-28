export default function Hero() {
  return (
    <section className="hero-modern">

      <div className="hero-text">
        <h1>Ride freely, explore more.</h1>
        <p>
          Premium bike rentals for city commuting and weekend adventures.
        </p>

        <div className="hero-buttons">
          <button>Browse Bikes</button>
          <button className="secondary">Book Now</button>
        </div>
      </div>

      <div className="hero-image">
        <img
          src="https://images.unsplash.com/photo-1509395176047-4a66953fd231?q=80&w=1200&auto=format&fit=crop"
          alt="Cycling"
        />
      </div>

    </section>
  );
}