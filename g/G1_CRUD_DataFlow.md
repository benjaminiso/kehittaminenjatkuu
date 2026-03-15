sequenceDiagram
    participant User as User (Browser)
    participant UI as Frontend (JS)
    participant API as Backend (Express)
    participant DB as PostgreSQL

    User->>UI: Fills form & Clicks "Save"
    UI->>API: POST /api/resources (Payload: JSON)
    
    alt Success
        API->>DB: INSERT INTO resources...
        DB-->>API: Returns new record
        API-->>UI: 201 Created (JSON: {ok: true, data: {...}})
        UI-->>User: Shows success message & updates list
    else Validation Fails (e.g. Missing name)
        API-->>UI: 400 Bad Request (JSON: {ok: false, error: "..."})
        UI-->>User: Shows validation error message
    end
