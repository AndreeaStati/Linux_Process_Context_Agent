from html import escape


def render_events_page(records: list, limit: int) -> str:
    rows = ""

    for record in reversed(records):
        event = record.get("event", {})
        event_info = event.get("event", {})
        process = event.get("process", {})
        parent = process.get("parent", {})
        user = event.get("user", {})
        detection = event.get("edr", {}).get("detection", {})

        received_at = escape(str(record.get("received_at", "")))
        timestamp = escape(str(event.get("@timestamp", "")))
        action = escape(str(event_info.get("action", "")))
        process_name = escape(str(process.get("name", "")))
        pid = escape(str(process.get("pid", "")))
        ppid = escape(str(parent.get("pid", "")))
        user_name = escape(str(user.get("name", "")))
        command_line = escape(str(process.get("command_line", "")))
        matched = detection.get("matched", False)

        matched_label = "DA" if matched else "NU"
        matched_class = "matched" if matched else "clean"

        rows += f"""
        <tr>
            <td>{received_at}</td>
            <td>{timestamp}</td>
            <td>{action}</td>
            <td>{process_name}</td>
            <td>{pid}</td>
            <td>{ppid}</td>
            <td>{user_name}</td>
            <td class="{matched_class}">{matched_label}</td>
            <td><code>{command_line}</code></td>
        </tr>
        """

    return f"""
    <!DOCTYPE html>
    <html lang="ro">
    <head>
        <meta charset="utf-8">
        <title>EDR Event Receiver</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 30px;
                background: #f6f8fa;
                color: #222;
            }}

            h1 {{
                margin-bottom: 5px;
            }}

            .subtitle {{
                color: #555;
                margin-bottom: 20px;
            }}

            .status {{
                display: inline-block;
                padding: 6px 10px;
                background: #e7f7ec;
                border: 1px solid #b7e2c1;
                border-radius: 6px;
                color: #176b2c;
                font-weight: bold;
            }}

            form {{
                margin: 20px 0;
            }}

            input {{
                padding: 6px;
                width: 70px;
            }}

            button {{
                padding: 7px 12px;
                cursor: pointer;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                background: white;
                font-size: 14px;
            }}

            th, td {{
                border: 1px solid #ddd;
                padding: 8px;
                vertical-align: top;
            }}

            th {{
                background: #24292f;
                color: white;
                text-align: left;
            }}

            tr:nth-child(even) {{
                background: #f2f2f2;
            }}

            code {{
                white-space: pre-wrap;
                word-break: break-word;
            }}

            .matched {{
                color: #b00020;
                font-weight: bold;
            }}

            .clean {{
                color: #1f7a1f;
                font-weight: bold;
            }}
        </style>
    </head>
    <body>
        <h1>Event Receiver</h1>
        <p class="subtitle">Vizualizarea ultimelor evenimente primite.</p>

        <p><span class="status">running</span></p>

        <p>
            Endpoint colectare:
            <code>POST /api/edr/events</code>
        </p>

        <form method="get" action="/ui">
            <label for="limit">Numar evenimente:</label>
            <input id="limit" name="limit" type="number" min="1" max="100" value="{limit}">
            <button type="submit">Afiseaza</button>
        </form>

        <table>
            <thead>
                <tr>
                    <th>received_at</th>
                    <th>@timestamp</th>
                    <th>action</th>
                    <th>process</th>
                    <th>PID</th>
                    <th>PPID</th>
                    <th>user</th>
                    <th>detection</th>
                    <th>command line</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </body>
    </html>
    """