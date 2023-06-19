function load_nodes_table() {
  // 创建style元素
  var style = document.createElement("style");

  //将CSS样式定义添加到style元素中
  style.innerHTML = `
  .blue-button {
    background-color: blue;
    color: white;
    border-radius: 10px; /* 设置圆角半径 */
    padding: 10px 20px; /* 设置内边距 */
  }
  .popup {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 400px;
    background-color: white;
    border-radius: 10px;
    padding: 20px;
    box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.5);
  }
  
  .popup-title {
    font-size: 18px;
    font-weight: bold;
    margin-bottom: 10px;
  }
  `;

// 将style元素插入到head元素中（或者其他适当的位置）
  document.head.appendChild(style);

  nodesTable = document.querySelector("#nodes");
  let i = 0;
  fetch("/nodes")
    .then((response) => response.json())
    .then((nodesList) => {
      //Once we fetch the list, we iterate over it
      nodesList.forEach((node) => {
        // console.log(node)
        // Create the table row
        row = document.createElement("tr");

        // Create the table data elements for the species and description columns
        var checkbox = document.createElement("INPUT");
        checkbox.type = "checkbox";
        checkbox.className = "nodes";
        checkbox.value = i;
        i = i + 1;
        var id= document.createElement("td");
        id.innerHTML = i;
        var check = document.createElement("td");
        var name = document.createElement("td");
        name.innerHTML = node.name;
        var location = document.createElement("td");
        location.innerHTML = node.address;
        var description = document.createElement("td");
        description.innerHTML = node.description;
        var port= document.createElement("td");
        port.innerHTML = node.scale_port;
        // Add the data elements to the row
        check.appendChild(checkbox);
        //row.appendChild(check);
        row.appendChild(id);
        row.appendChild(name);
        row.appendChild(location);
        row.appendChild(port);
        // 创建第一个按钮和对应的单元格
        var button1 = document.createElement("button");
        button1.innerHTML = "查看";
        button1.classList.add("blue-button"); // 添加CSS类名
        var cell1 = document.createElement("td");
        cell1.appendChild(button1);

        // 为button1添加一个点击事件监听器
        button1.addEventListener("click", function() {
          // 创建一个div元素作为弹出框
          var popup = document.createElement("div");
          popup.classList.add("popup");
        
          // 创建标题元素
          var title = document.createElement("h2");
          title.classList.add("popup-title");
          title.innerHTML = "节点公钥";
        
          // 将标题和其他内容添加到弹出框中
          popup.appendChild(title);
          popup.appendChild(document.createTextNode("公钥：8a3f7b95c6d248e1fb4cd7e5a0e937bc"));
        
          // 添加弹出框到body元素中
          document.body.appendChild(popup);
        });

        // 创建第二个按钮和对应的单元格
        var button2 = document.createElement("button");
        button2.innerHTML = "查看";
        button2.classList.add("blue-button"); // 添加CSS类名
        var cell2 = document.createElement("td");
        cell2.appendChild(button2);

        // 为button2添加一个点击事件监听器
        button2.addEventListener("click", function() {
          // 创建一个div元素作为弹出框
          var popup = document.createElement("div");
          popup.classList.add("popup");
        
          // 创建标题元素
          var title = document.createElement("h2");
          title.classList.add("popup-title");
          title.innerHTML = "节点公钥";
        
          // 将标题和其他内容添加到弹出框中
          popup.appendChild(title);
          popup.appendChild(document.createTextNode("公钥：8a3f7b95c6d248e1fb4cd7e5a0e937bc"));
        
          // 添加弹出框到body元素中
          document.body.appendChild(popup);
        });

        // 创建第三个按钮和对应的单元格
        var button3 = document.createElement("button");
        button3.innerHTML = "查看";
        button3.classList.add("blue-button"); // 添加CSS类名
        var cell3 = document.createElement("td");
        cell3.appendChild(button3);

        // 为button3添加一个点击事件监听器
        button3.addEventListener("click", function() {
          // 创建一个div元素作为弹出框
          var popup = document.createElement("div");
          popup.classList.add("popup");
        
          // 创建标题元素
          var title = document.createElement("h2");
          title.classList.add("popup-title");
          title.innerHTML = "节点公钥";
        
          // 将标题和其他内容添加到弹出框中
          popup.appendChild(title);
          popup.appendChild(document.createTextNode("公钥：8a3f7b95c6d248e1fb4cd7e5a0e937bc"));
        
          // 添加弹出框到body元素中
          document.body.appendChild(popup);
        });
        
        // 将三个单元格依次添加到新的行元素中
        row.appendChild(cell1);
        row.appendChild(cell2);
        row.appendChild(cell3);
        nodesTable.appendChild(row);
      });
    });
}

async function getNodes() {
  let nodes = [];
  await fetch("/nodes")
    .then((response) => response.json())
    .then((nodesList) => {
      //Once we fetch the list, we iterate over it
      nodesList.forEach((node) => {
        nodes.push([
          node.name,
          node.address,
          node.scale_port,
          node.mpc_pub_key,
          node.scale_key,
        ]);
      });
    });
  return nodes;
}

function getSelectedIndexes(className) {
  var selectedNodes = [];
  var checkboxes = document.querySelectorAll("input:checked");

  for (var i = 0; i < checkboxes.length; i++) {
    if (checkboxes[i].className == className) {
      selectedNodes.push(parseInt(checkboxes[i].value));
    }
  }

  return selectedNodes;
}

function getSelectedValue(className) {
  var checkboxes = document.querySelectorAll("input:checked");

  var funcName;
  for (var i = 0; i < checkboxes.length; i++) {
    if (checkboxes[i].className == className) {
      funcName = checkboxes[i].value;
    }
  }

  return funcName;
}

// var functList = ["avg", "max", "stats"]
// demo use of MPC computation
async function mpc_computation() {
  document.getElementById("errorMsg").style.display = "none";
  // get information about selected nodes
  var selectedNodesIndexes = getSelectedIndexes("nodes");
  if (selectedNodesIndexes.length != 3) {
    document.getElementById("errorMsg").innerText = "Error: select 3 nodes.";
    document.getElementById("errorMsg").style.display = "block";
    console.log("select 3 nodes");
    return;
  }
  let allNodes = await getNodes();
  let nodes = [
    allNodes[selectedNodesIndexes[0]],
    allNodes[selectedNodesIndexes[1]],
    allNodes[selectedNodesIndexes[2]],
  ];
  var nodesNames = nodes[0][0] + "," + nodes[1][0] + "," + nodes[2][0];

  // get information about selected nodes
  var selectedDatasets = getSelectedIndexes("datasets");
  if (selectedDatasets.length == 0) {
    document.getElementById("errorMsg").innerText =
      "Error: no dataset selected.";
    document.getElementById("errorMsg").style.display = "block";
    document.getElementById("errorMsg").style.color = "red";
    console.log("no dataset selected");
    return;
  }
  let datasets = await getDatasets();
  let datasetNames = "";
  let columns = datasets[selectedDatasets[0]][2].split(",");
  let allowedNodes = nodesNames.split(",");
  for (var i = 0; i < selectedDatasets.length; i++) {
    datasetNames = datasetNames + "," + datasets[selectedDatasets[i]][0];
    columns = columns.filter((value) =>
      datasets[selectedDatasets[i]][2].split(",").includes(value)
    );
    if (datasets[selectedDatasets[i]][3] != "all") {
      allowedNodes = allowedNodes.filter((value) =>
        datasets[selectedDatasets[i]][3].split(",").includes(value)
      );
    }
  }
  datasetNames = datasetNames.substring(1);

  if (columns.length == 0) {
    document.getElementById("errorMsg").innerText =
      "Error: datasets incompatible.";
    document.getElementById("errorMsg").style.display = "block";
    document.getElementById("errorMsg").style.color = "red";
    console.log("datasets incompatible");
    return;
  }
  if (allowedNodes.length != 3) {
    document.getElementById("errorMsg").innerText =
      "Error: a dataset not shared with the selected nodes.";
    document.getElementById("errorMsg").style.display = "block";
    document.getElementById("errorMsg").style.color = "red";
    console.log("a dataset not shared with the selected nodes");
    return;
  }

  // define the name of the function that will be computed
  var funcName = getSelectedValue("function");

  var params = {};
  if (funcName == "k-means") {
    params["NUM_CLUSTERS"] = document.getElementById("num_clusters").value;
    if ((!(parseInt(params["NUM_CLUSTERS"]) > 1)) || (parseInt(params["NUM_CLUSTERS"]) > 5)) {
      document.getElementById("errorMsg").innerText =
        "Error: input of number of clusters should at least 2 and at most 5.";
      document.getElementById("errorMsg").style.display = "block";
      document.getElementById("errorMsg").style.color = "red";
      console.log("error with input of number of clusters");
      return;
    }
    document.getElementById("errorMsg").innerText =
        "Computing k-means is a complex operation that might take some time.";
    document.getElementById("errorMsg").style.display = "block";
    document.getElementById("errorMsg").style.color = "black";
  }

  var progressBar = document.querySelector("progress[id=progressBar]");
  progressBar.removeAttribute("value");

  // generate public and private key of the buyer
  let keypair = GenerateKeypair();
  let pubKey = keypair[0];
  let secKey = keypair[1];

  // send requests
  console.log("Sending requests to manager");

  var msg = {
    NodesNames: nodesNames,
    Program: funcName,
    DatasetNames: datasetNames,
    ReceiverPubKey: pubKey,
    Params: JSON.stringify(params),
  };

  // timeout 1h
  let rawResponse
  try {
    rawResponse = await fetchWithTimeout("/compute", msg, {
      timeout: 60 * 60 * 1000,
    });
  }
  catch (err) {
    document.getElementById("errorMsg").innerText =
        "Error: " + err.message;
    document.getElementById("errorMsg").style.display = "block";
    document.getElementById("errorMsg").style.color = "red";
    console.log("error computing the function");
    return;
  }


  let response = await rawResponse.json();
  console.log("Response obtained");

  let res = JoinSharesShamir(
    pubKey,
    secKey,
    response[0].Result,
    response[1].Result,
    response[2].Result
  );

  // interpret the result
  let csvText = VecToCsvText(res, response[0].Cols, funcName);
  // console.log("result", csvText)

  download(csvText, "result.csv");

  progressBar.value = 100;
  document.getElementById("errorMsg").innerText =
    "Success: see downloaded file.";
  document.getElementById("errorMsg").style.display = "block";
  document.getElementById("errorMsg").style.color = "green";
}

function download(textToWrite, name) {
  var a = document.body.appendChild(document.createElement("a"));
  a.download = name;
  textToWrite = textToWrite.replace(/\n/g, "%0D%0A");
  a.href = "data:text/plain," + textToWrite;
  a.click();
}

async function fetchWithTimeout(resource, msg, options = {}) {
  const { timeout = 8000 } = options;

  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(resource, {
      ...options,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      method: "post",
      body: JSON.stringify(msg),
    });
    clearTimeout(id);
    return response;
  }
  catch (err) {
    return err.message
  }
}
