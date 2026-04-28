// index.js
// Enhanced custom validation – NO TABLE REQUIRED

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("booking-form");
    if (!form) return;

    form.addEventListener("submit", (event) => {
        event.preventDefault();

        const fullname = document.getElementById("fullname").value.trim();
        const email = document.getElementById("email").value.trim();
        const bike = document.getElementById("bike").value.trim();
        const rentdate = document.getElementById("rentdate").value;
        const returndate = document.getElementById("returndate").value;
        const terms = document.getElementById("terms").checked;

        const errors = {
            fullname: document.getElementById("fullnameError"),
            email: document.getElementById("emailError"),
            bike: document.getElementById("bikeError"),
            rentdate: document.getElementById("rentdateError"),
            returndate: document.getElementById("returndateError"),
            terms: document.getElementById("termsError"),
        };

        // Clear old errors
        Object.values(errors).forEach(e => e.textContent = "");

        let valid = true;

        // FULL NAME
        if (fullname === "") {
            errors.fullname.textContent = "Full name is required.";
            valid = false;
        } else if (fullname.split(" ").length < 2) {
            errors.fullname.textContent = "Please write your full name (first + last).";
            valid = false;
        } else if (!/^[A-Za-z\s'-]{3,}$/.test(fullname)) {
            errors.fullname.textContent = "Name contains invalid characters.";
            valid = false;
        }

        // EMAIL
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (email === "") {
            errors.email.textContent = "Email is required.";
            valid = false;
        } else if (!emailPattern.test(email)) {
            errors.email.textContent = "Please enter a valid email (example: user@domain.com).";
            valid = false;
        }

        // BIKE
        if (bike === "") {
            errors.bike.textContent = "You must select a bike.";
            valid = false;
        }

        // RENT DATE
        if (rentdate === "") {
            errors.rentdate.textContent = "Please choose a rent date.";
            valid = false;
        } else {
            const today = new Date().toISOString().split("T")[0];
            if (rentdate < today) {
                errors.rentdate.textContent = "Rent date cannot be in the past.";
                valid = false;
            }
        }

        // RETURN DATE
        if (returndate === "") {
            errors.returndate.textContent = "Please choose a return date.";
            valid = false;
        } else if (rentdate && returndate < rentdate) {
            errors.returndate.textContent = "Return date must be after rent date.";
            valid = false;
        }

        // TERMS
        if (!terms) {
            errors.terms.textContent = "You must accept the terms to proceed.";
            valid = false;
        }

        // If invalid, stop here
        if (!valid) return;

        // If valid, you can do something here (send data, show popup, etc.)
        alert("Booking submitted successfully!");
        form.reset();
    });
});

