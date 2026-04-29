export default function Productcard({ image, title, text, price }) {
  return (
    <article className="product-card">
      <img src={image} alt={title} />
      <h4>{title}</h4>
      <p>{text}</p>
      <span>{price}</span>
    </article>
  );
}