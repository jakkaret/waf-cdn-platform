import asyncio
from api.analytics import get_analytics_summary

async def main():
    res = await get_analytics_summary({"role": "admin"})
    print("Analytics Summary Output:")
    print(res)

if __name__ == "__main__":
    asyncio.run(main())
