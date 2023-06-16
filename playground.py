class User:
    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = password
        self.posts = []


class BlogPost:
    def __init__(self, title, subtitle, body):
        self.title = title
        self.subtitle = subtitle
        self.body = body


new_post = BlogPost(title="Cool title", subtitle="so cool",
                    body="blah blah")

new_user = User("Giorgio", "gmail.com", "12345")

new_user.posts = {
    "title": new_post.title,
    "subtitle": new_post.subtitle,
    "body": new_post.body,
}
print(new_user.posts)
