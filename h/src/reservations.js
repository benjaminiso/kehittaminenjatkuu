// src/js/reservations.js
document.addEventListener('DOMContentLoaded', () => {
  const container = document.getElementById('reservations-container');

  // --- Step 1: Inject reservation form dynamically ---
  const formContainer = document.createElement('div');
  formContainer.id = 'reservation-form-container';
  formContainer.className = 'hidden rounded-3xl bg-white p-8 shadow-soft mb-6';
  formContainer.innerHTML = `
    <form id="reservation-form" class="flex flex-col gap-4">
      <label>
        Name:
        <input type="text" name="name" required class="border border-gray-300 p-2 rounded w-full">
      </label>
      <label>
        Date:
        <input type="date" name="date" required class="border border-gray-300 p-2 rounded w-full">
      </label>
      <label>
        Time:
        <input type="time" name="time" required class="border border-gray-300 p-2 rounded w-full">
      </label>
      <label>
        Duration (hours):
        <input type="number" name="duration" min="1" required class="border border-gray-300 p-2 rounded w-full">
      </label>
      <label>
        Resource (ID):
        <input type="number" name="resource" required class="border border-gray-300 p-2 rounded w-full">
      </label>
      <label>
        Note:
        <input type="text" name="note" class="border border-gray-300 p-2 rounded w-full">
      </label>
      <div class="flex gap-2 mt-2">
        <button type="submit" class="rounded-2xl bg-brand-primary px-6 py-3 text-white font-semibold hover:bg-brand-dark/80">Save</button>
        <button type="button" id="cancel-form" class="rounded-2xl bg-gray-200 px-6 py-3 font-semibold hover:bg-gray-300">Cancel</button>
      </div>
    </form>
  `;
  container.parentElement.insertBefore(formContainer, container);
  const form = document.getElementById('reservation-form');

  // --- Step 2: Show/hide form logic ---
  document.getElementById('new-reservation').addEventListener('click', () => {
    formContainer.classList.remove('hidden'); // show form
    form.dataset.editId = '';                  // new reservation
    form.reset();
  });

  document.getElementById('cancel-form').addEventListener('click', () => {
    formContainer.classList.add('hidden');    // hide form
    form.reset();
  });

  // --- Step 3: Load reservations ---
  async function loadReservations() {
    try {
      const res = await fetch('/api/reservations');
      const data = await res.json();
      if (!data.ok) throw new Error(data.error);

      container.innerHTML = data.data.map(r => `
        <div class="rounded-2xl bg-white p-6 shadow-soft flex flex-col gap-2">
          <p><strong>Resource:</strong> ${r.resource_name}</p>
          <p><strong>User:</strong> ${r.user_email}</p>
          <p><strong>Start:</strong> ${new Date(r.start_time).toLocaleString()}</p>
          <p><strong>End:</strong> ${new Date(r.end_time).toLocaleString()}</p>
          <p><strong>Note:</strong> ${r.note || '-'}</p>
          <p><strong>Status:</strong> ${r.status}</p>
          <div class="mt-2 flex gap-2">
            <button class="edit-btn rounded-2xl bg-brand-blue px-4 py-2 text-white font-semibold hover:bg-brand-dark/80" data-id="${r.id}">
              Edit
            </button>
            <button class="delete-btn rounded-2xl bg-brand-rose px-4 py-2 text-white font-semibold hover:bg-brand-dark/80" data-id="${r.id}">
              Delete
            </button>
          </div>
        </div>
      `).join('');
    } catch (err) {
      container.innerHTML = `<p class="text-red-500">Error loading reservations: ${err.message}</p>`;
    }
  }

  loadReservations();

  // --- Step 4: Form submission logic (Create / Update) ---
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = Object.fromEntries(new FormData(form));

    const startTime = new Date(`${formData.date}T${formData.time}`).toISOString();
    const endTime = new Date(Date.parse(startTime) + formData.duration * 3600000).toISOString();

    const payload = {
      resourceId: formData.resource,
      userId: 1, // TODO: replace with logged-in user ID
      startTime,
      endTime,
      note: formData.note || '',
      status: 'active'
    };

    try {
      let res;
      if (form.dataset.editId) {
        // Update existing reservation
        res = await fetch(`/api/reservations/${form.dataset.editId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        if (!res.ok) throw new Error('Failed to update reservation');
        alert('Reservation updated!');
      } else {
        // Create new reservation
        res = await fetch('/api/reservations', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        if (res.status !== 201) throw new Error('Failed to create reservation');
        alert('Reservation created!');
      }

      form.reset();
      formContainer.classList.add('hidden');
      form.dataset.editId = '';
      loadReservations();

    } catch (err) {
      alert('Error: ' + err.message);
    }
  });

  // --- Step 5: Delegate Edit/Delete buttons ---
  container.addEventListener('click', async (e) => {
    const id = e.target.dataset.id;
    if (!id) return;

    // DELETE
    if (e.target.classList.contains('delete-btn')) {
      if (!confirm('Are you sure you want to delete this reservation?')) return;
      try {
        const res = await fetch(`/api/reservations/${id}`, { method: 'DELETE' });
        if (res.status === 204) {
          alert('Reservation deleted!');
          loadReservations();
        } else {
          const errData = await res.json();
          throw new Error(errData.error || 'Failed to delete reservation');
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }

    // EDIT
    if (e.target.classList.contains('edit-btn')) {
      try {
        const rRes = await fetch(`/api/reservations/${id}`);
        const rData = await rRes.json();
        if (!rData.ok) throw new Error(rData.error);
        const reservation = rData.data;

        // Populate form for editing
        formContainer.classList.remove('hidden');
        form.dataset.editId = id;
        form.name.value = reservation.user_email || '';
        form.date.value = reservation.start_time.split('T')[0];
        form.time.value = reservation.start_time.split('T')[1].slice(0,5);
        form.duration.value = (new Date(reservation.end_time) - new Date(reservation.start_time)) / 3600000;
        form.resource.value = reservation.resource_id;
        form.note.value = reservation.note || '';

      } catch (err) {
        alert('Error: ' + err.message);
      }
    }
  });

});