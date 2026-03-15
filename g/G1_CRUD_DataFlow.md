# Booking System: CRUD Data Flow (Alternative Version)

This version shows the same Create, Read, Update, Delete operations using slightly different diagram conventions.

## 1. CREATE (C)

```mermaid
sequenceDiagram
    participant Browser as User (Browser)
    participant Frontend as UI (JS)
    participant Server as API (Express)
    participant Database as PostgreSQL

    Browser->>Frontend: Fill form & click "Save"
    Frontend->>Server: POST /api/resources with JSON payload
    Server->>Database: INSERT INTO resources
    
    alt Resource successfully created
        Database-->>Server: New record returned
        Server-->>Frontend: 201 Created + JSON data
        Frontend-->>Browser: Show success & update list
    else Validation or duplicate error
        Server-->>Frontend: 400 or 409 error + message
        Frontend-->>Browser: Show error message
    end
```
## 2. READ (R)

```mermaid
sequenceDiagram
    participant Browser as User (Browser)
    participant Frontend as UI (JS)
    participant Server as API (Express)
    participant Database as PostgreSQL

    Browser->>Frontend: Open page / refresh
    Frontend->>Server: GET /api/resources
    Server->>Database: SELECT * FROM resources
    
    alt Data retrieved successfully
        Database-->>Server: Returns rows
        Server-->>Frontend: 200 OK + JSON data
        Frontend-->>Browser: Render resource list
    else Database / server error
        Server-->>Frontend: 500 Internal Server Error
        Frontend-->>Browser: Show "Failed to load data"
    end
```

    
## 3. UPDATE (U)

```mermaid
sequenceDiagram
    participant Browser as User (Browser)
    participant Frontend as UI (JS)
    participant Server as API (Express)
    participant Database as PostgreSQL

    Browser->>Frontend: Edit resource & submit
    Frontend->>Server: PUT /api/resources/:id with JSON
    Server->>Database: UPDATE resources WHERE id=:id
    
    alt Update successful
        Database-->>Server: Updated record
        Server-->>Frontend: 200 OK + JSON
        Frontend-->>Browser: Update UI with new data
    else Validation error
        Server-->>Frontend: 400 Bad Request
        Frontend-->>Browser: Show validation error
    else Resource not found
        Server-->>Frontend: 404 Not Found
        Frontend-->>Browser: Show "Resource not found"
    end
```
## 4. DELETE (D)

```mermaid
sequenceDiagram
    participant Browser as User (Browser)
    participant Frontend as UI (JS)
    participant Server as API (Express)
    participant Database as PostgreSQL

    Browser->>Frontend: Click delete & confirm
    Frontend->>Server: DELETE /api/resources/:id
    Server->>Database: DELETE FROM resources WHERE id=:id
    
    alt Deletion successful
        Database-->>Server: Confirm deleted
        Server-->>Frontend: 200 OK / 204 No Content
        Frontend-->>Browser: Remove item from UI
    else Resource not found
        Server-->>Frontend: 404 Not Found
        Frontend-->>Browser: Show error "Item already deleted"
    end
```