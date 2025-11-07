rule hello_world_str {
    meta:
        description = "A demo of YARA rules"
        author = "..."

    strings:
        $hello = "Hello, World"

    condition:
        $hello
}