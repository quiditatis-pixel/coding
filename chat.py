import os
import anthropic

# 设置环境变量
os.environ["ANTHROPIC_BASE_URL"] = "https://api.minimaxi.com/anthropic"
os.environ["ANTHROPIC_API_KEY"] = "sk-api-oAxZCqZw06O48F6x6Gbc1ODmLxqZ6c9lhrAnRFcHRFmrROp5N8VrZcV27bhaQ9t9S3GDBqg5XZ-ZWW-lo7DXyrUvsC3VtxlOj3z_eJTCuPVClbSVrL62D4A"

client = anthropic.Anthropic()

message = client.messages.create(
    model="MiniMax-M2.1",
    max_tokens=1000,
    system="You are a helpful assistant.",
    messages=[
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": "我叫周熙元，我是一个大胖子，请帮我写一个自我介绍，包括我的名字、年龄、爱好、特长、职业等。"
                }
            ]
        }
    ]
)

for block in message.content:
    if block.type == "thinking":
        print(f"Thinking:\n{block.thinking}\n")
    elif block.type == "text":
        print(f"Text:\n{block.text}\n")