# Simple CVE Data Test

```js
const weeklyData = await FileAttachment("data/cve-weekly.json").json();
```

Data loaded: ${weeklyData ? "✅" : "❌"}

Data type: ${typeof weeklyData}

Is array: ${Array.isArray(weeklyData)}

Length: ${weeklyData?.length}

First item: ${JSON.stringify(weeklyData?.[0], null, 2)}