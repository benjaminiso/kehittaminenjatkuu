import { useState } from "react";

import Navbar from "./components/Navbar";
import Footer from "./components/Footer";

import Home from "./pages/Home";
import Catalog from "./pages/Catalog";
import Bookings from "./pages/Bookings";

export default function App() {
  const [page, setPage] = useState("home");

  const renderPage = () => {
    if (page === "catalog") return <Catalog />;
    if (page === "bookings") return <Bookings />;
    return <Home />;
  };

  return (
    <div className="container">
      <Navbar setPage={setPage} />

      <main>
        {renderPage()}
      </main>

      <Footer />
    </div>
  );
}