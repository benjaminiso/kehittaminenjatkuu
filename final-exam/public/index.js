const API_URL = "http://localhost:3000/api/persons";

/* =========================
   LOAD ALL CUSTOMERS
========================= */
async function loadCustomers() {
  const container = document.getElementById("customer-list");

  try {
    const res = await fetch(API_URL);

    if (!res.ok) {
      throw new Error(`HTTP error! status: ${res.status}`);
    }

    const data = await res.json();

    container.innerHTML = "";

    if (!Array.isArray(data) || data.length === 0) {
      container.innerHTML = "<p>No customers found.</p>";
      return;
    }

    data.forEach(person => {
      const div = document.createElement("div");
      div.className = "customer-card";

      div.innerHTML = `
        <strong>${person.first_name} ${person.last_name}</strong><br>
        Email: ${person.email}<br>
        Phone: ${person.phone || "-"}
      `;

      // CLICK → LOAD INTO FORM
      div.addEventListener("click", () => {
        document.getElementById("customer-id").value = person.id;
        document.getElementById("firstName").value = person.first_name || "";
        document.getElementById("lastName").value = person.last_name || "";
        document.getElementById("email").value = person.email || "";
        document.getElementById("phone").value = person.phone || "";
        document.getElementById("birthDate").value = person.birth_date
          ? person.birth_date.split("T")[0]
          : "";
      });

      container.appendChild(div);
    });

  } catch (err) {
    console.error("Load error:", err);
    container.innerHTML = "<p style='color:red;'>Error loading customers</p>";
  }
}

/* =========================
   CREATE / UPDATE CUSTOMER
========================= */
document.getElementById("form").addEventListener("submit", async (e) => {
  e.preventDefault();

  const id = document.getElementById("customer-id").value;

  const customer = {
    first_name: document.getElementById("firstName").value.trim(),
    last_name: document.getElementById("lastName").value.trim(),
    email: document.getElementById("email").value.trim(),
    phone: document.getElementById("phone").value.trim(),
    birth_date: document.getElementById("birthDate").value
  };

  try {
    let res;

    if (id) {
      // UPDATE
      res = await fetch(`${API_URL}/${id}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(customer)
      });
    } else {
      // CREATE
      res = await fetch(API_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(customer)
      });
    }

    if (!res.ok) {
      const errorText = await res.text();
      throw new Error(errorText);
    }

    document.getElementById("form").reset();
    document.getElementById("customer-id").value = "";

    loadCustomers();

  } catch (err) {
    console.error("Save error:", err);
    alert("Failed to save customer. Check console.");
  }
});

/* =========================
   DELETE CUSTOMER
========================= */
document.getElementById("deleteBtn").addEventListener("click", async () => {
  const id = document.getElementById("customer-id").value;

  if (!id) {
    alert("Select a customer first");
    return;
  }

  try {
    const res = await fetch(`${API_URL}/${id}`, {
      method: "DELETE"
    });

    if (!res.ok) {
      throw new Error(`Delete failed: ${res.status}`);
    }

    document.getElementById("form").reset();
    document.getElementById("customer-id").value = "";

    loadCustomers();

  } catch (err) {
    console.error("Delete error:", err);
    alert("Failed to delete customer.");
  }
});

/* =========================
   INITIAL LOAD
========================= */
loadCustomers();