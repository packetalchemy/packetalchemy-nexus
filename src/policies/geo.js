export function getRegion(country = "AUTO") {
    switch (country.toUpperCase()) {
      case "DE":
        return "Europe";
  
      case "TR":
        return "Turkey";
  
      case "US":
        return "NorthAmerica";
  
      default:
        return "Auto";
    }
  }