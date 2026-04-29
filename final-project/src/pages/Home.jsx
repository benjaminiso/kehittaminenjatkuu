import Hero from "../components/Hero";
import CTA from "../components/CTA";
import Productcard from "../components/Productcard";

export default function Home() {
  return (
    <main className="home">

      <Hero />

      <section className="section">
        <h2>About Voltbikesuper</h2>
        <p className="text-muted">
          Premium bikes for city, trail, and road adventures. Built for comfort, speed, and reliability.
        </p>
      </section>

      <section className="section">
        <h2>Popular Bikes</h2>

        <div className="product-grid compact">

          <Productcard
            image="/Pictures/citybike.jpg"
            title="City Cruiser"
            text="Comfortable city riding"
            price="39 €/d"
          />

          <Productcard
            image="/Pictures/mountainbike.jpg"
            title="Trail Explorer"
            text="Off-road ready"
            price="49 €/d"
          />

          <Productcard
            image="/Pictures/roadbike.webp"
            title="Road Runner"
            text="Fast and lightweight"
            price="59 €/d"
          />

        </div>
      </section>

      <CTA />

    </main>
  );
}