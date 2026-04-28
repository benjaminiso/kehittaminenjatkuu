import Navbar from "./components/Navbar";
import Home from "./pages/Home";
import Catalog from "./pages/Catalog";
import Bookings from "./pages/Bookings";

export default function App() {
  return (
    <>
      <Navbar />

      <Home />
      <Catalog />
      <Bookings />
    </>
  );
}