// src/js/reservations.js
document.addEventListener('DOMContentLoaded', () => {
  const container = document.getElementById('reservations-container');

  // --- Load all reservations ---
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
            <button class="update-btn rounded-lg bg-brand-blue px-4 py-2 text-white text-sm font-semibold hover:bg-brand-dark/80" data-id="${r.id}">
              Update
            </button>
            <button class="delete-btn rounded-lg bg-brand-rose px-4 py-2 text-white text-sm font-semibold hover:bg-brand-dark/80" data-id="${r.id}">
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

  // --- Create new reservation ---
  document.getElementById('new-reservation').addEventListener('click', async () => {
    const newRes = {
      resourceId: 2,
      userId: 1,
      startTime: new Date().toISOString(),
      endTime: new Date(Date.now() + 3600000).toISOString(),
      note: 'Team meeting',
      status: 'active'
    };

    try {
      const res = await fetch('/api/reservations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newRes)
      });

      if (res.status === 201) {
        alert('Reservation created!');
        loadReservations();
      } else {
        const errData = await res.json();
        throw new Error(errData.error || 'Failed to create reservation');
      }
    } catch (err) {
      alert('Error: ' + err.message);
    }
  });

  // --- Delegate Update/Delete buttons ---
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

    // UPDATE (simple demo: toggle status between active/inactive)
    if (e.target.classList.contains('update-btn')) {
      try {
        // fetch current reservation first
        const rRes = await fetch(`/api/reservations/${id}`);
        const rData = await rRes.json();
        if (!rData.ok) throw new Error(rData.error);
        const reservation = rData.data;

        const updated = { ...reservation };
        updated.status = reservation.status === 'active' ? 'inactive' : 'active';

        const putRes = await fetch(`/api/reservations/${id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(updated)
        });

        if (putRes.status === 200) {
          alert('Reservation updated!');
          loadReservations();
        } else {
          const errData = await putRes.json();
          throw new Error(errData.error || 'Failed to update reservation');
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }
  });
});