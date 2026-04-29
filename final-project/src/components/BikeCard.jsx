export default function BikeCard({ image, title, text, price }) {
  return (
    <div className="bike-card">

      <img src={image} alt={title} />

      <div className="bike-info">
        <h3>{title}</h3>
        <p>{text}</p>

        <div className="bike-footer">
          <span>{price}</span>
          <button>Rent</button>
        </div>
      </div>

    </div>
  );
}