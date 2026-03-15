# CRUD Data Flow for Booking System

This file contains **Mermaid sequence diagrams** showing the data flow for each CRUD operation in the Booking System assignment.  

Participants:

- **U** = User (Browser)  
- **F** = Frontend (form.js and resources.js)  
- **B** = Backend (Express Route)  
- **V** = express-validator  
- **S** = Resource Service  
- **DB** = PostgreSQL

---

## 1️⃣ CREATE

```mermaid
sequenceDiagram
    participant U as User (Browser)
    participant F as Frontend (form.js and resources.js)
    participant B as Backend (Express Route)
    participant V as express-validator
    participant S as Resource Service
    participant DB as PostgreSQL

    U->>F: Submit form
    F->>F: Client-side validation
    F->>B: POST /api/resources (JSON)

    B->>V: Validate request
    V-->>B: Validation result

    alt Validation fails
        B-->>F: 400 Bad Request + errors[]
        F-->>U: Show validation message
    else Validation OK
        B->>S: create Resource(data)
        S->>DB: INSERT INTO resources
        DB-->>S: Result / Duplicate error

        alt Duplicate
            S-->>B: Duplicate detected
            B-->>F: 409 Conflict
            F-->>U: Show duplicate message
        else Success
            S-->>B: Created resource
            B-->>F: 201 Created
            F-->>U: Show success message
        end
    end

    sequenceDiagram
    participant U as User (Browser)
    participant F as Frontend (form.js and resources.js)
    participant B as Backend (Express Route)
    participant S as Resource Service
    participant DB as PostgreSQL

    U->>F: Open resources page
    F->>B: GET /api/resources

    B->>S: fetch all resources
    S->>DB: SELECT * FROM resources
    DB-->>S: Result / Error

    alt Success
        S-->>B: Resource list
        B-->>F: JSON data
        F-->>U: Render resource list
    else Error
        S-->>B: 500 Internal Server Error
        B-->>F: Show error message
        F-->>U: Show error message
    end

    sequenceDiagram
    participant U as User (Browser)
    participant F as Frontend (form.js and resources.js)
    participant B as Backend (Express Route)
    participant V as express-validator
    participant S as Resource Service
    participant DB as PostgreSQL

    U->>F: Edit resource form
    F->>F: Client-side validation
    F->>B: PUT /api/resources/:id (JSON)

    B->>V: Validate request
    V-->>B: Validation result

    alt Validation fails
        B-->>F: 400 Bad Request + errors[]
        F-->>U: Show validation message
    else Validation OK
        B->>S: update Resource(id, data)
        S->>DB: UPDATE resources SET ... WHERE id=...
        DB-->>S: Result / Not found

        alt Not found
            S-->>B: 404 Not Found
            B-->>F: Show not found message
            F-->>U: Show error
        else Success
            S-->>B: Updated resource
            B-->>F: 200 OK
            F-->>U: Show success message
        end
    end

    sequenceDiagram
    participant U as User (Browser)
    participant F as Frontend (form.js and resources.js)
    participant B as Backend (Express Route)
    participant S as Resource Service
    participant DB as PostgreSQL

    U->>F: Click delete resource
    F->>B: DELETE /api/resources/:id

    B->>S: delete Resource(id)
    S->>DB: DELETE FROM resources WHERE id=...
    DB-->>S: Result / Not found

    alt Not found
        S-->>B: 404 Not Found
        B-->>F: Show not found message
        F-->>U: Show error
    else Success
        S-->>B: Resource deleted
        B-->>F: 200 OK / 204 No Content
        F-->>U: Show success message
    end