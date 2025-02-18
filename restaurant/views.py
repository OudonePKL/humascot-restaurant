from rest_framework import generics, status
from rest_framework.response import Response
from .models import (
    Restaurant,
    Category,
    Employee,
    Table,
    Point,
    MenuItem,
    Order,
    OrderItem,
)
from .serializers import (
    RestaurantSerializer,
    CategorySerializer,
    CategoryMangeSerializer,
    EmployeeSerializer,
    TableSerializer,
    TableManageSerializer,
    PointSerializer,
    MenuItemSerializer,
    MenuItemManageSerializer,
    OrderSerializer,
    OrderManageSerializer,
    OrderItemSerializer,
    OrderCancelSerializer,
    OrderItemCancelSerializer,
)


class RestaurantCreateView(generics.ListCreateAPIView):
    queryset = Restaurant.objects.all()
    serializer_class = RestaurantSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Restaurant created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {"message": "Failed to create restaurant", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


class RestaurantCreateView(generics.ListCreateAPIView):
    queryset = Restaurant.objects.all()
    serializer_class = RestaurantSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Restaurant created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {"message": "Failed to create restaurant", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


class RestaurantDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Restaurant.objects.all()
    serializer_class = RestaurantSerializer

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Restaurant updated successfully", "data": serializer.data},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"message": "Failed to update restaurant", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(
            {"message": "Restaurant deleted successfully"},
            status=status.HTTP_200_OK,
        )


# Category management
class CategoryListView(generics.ListAPIView):
    serializer_class = CategorySerializer

    def get_queryset(self):
        return Category.objects.filter(restaurant_id=self.kwargs["restaurant_pk"])


class CategoryCreateView(generics.CreateAPIView):
    serializer_class = CategoryMangeSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            restaurant = Restaurant.objects.get(pk=self.kwargs["restaurant_pk"])
            serializer.save(restaurant=restaurant)
            return Response(
                {"message": "Category created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {"message": "Failed to create category", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


class CategoryDetailView(generics.RetrieveAPIView):
    serializer_class = CategorySerializer

    def get_queryset(self):
        return Category.objects.filter(restaurant_id=self.kwargs["restaurant_pk"])


class CategoryUpdateView(generics.UpdateAPIView):
    queryset = Category.objects.all()
    serializer_class = CategoryMangeSerializer

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Category updated successfully", "data": serializer.data},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"message": "Failed to update category", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


class CategoryDestroyView(generics.DestroyAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(
            {"message": "Category deleted successfully"},
            status=status.HTTP_200_OK,
        )


# Employee management
class EmployeeListView(generics.ListAPIView):
    serializer_class = EmployeeSerializer

    def get_queryset(self):
        return Employee.objects.filter(restaurant_id=self.kwargs["restaurant_pk"])


class EmployeeCreateView(generics.CreateAPIView):
    serializer_class = EmployeeSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            restaurant = Restaurant.objects.get(pk=self.kwargs["restaurant_pk"])
            serializer.save(restaurant=restaurant)
            return Response(
                {"message": "Employee created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {"message": "Failed to create employee", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


class EmployeeDetailView(generics.RetrieveAPIView):
    serializer_class = EmployeeSerializer

    def get_queryset(self):
        return Employee.objects.filter(restaurant_id=self.kwargs["restaurant_pk"])


class EmployeeUpdateView(generics.UpdateAPIView):
    queryset = Employee.objects.all()
    serializer_class = EmployeeSerializer

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Employee updated successfully", "data": serializer.data},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"message": "Failed to update employee", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


class EmployeeDestroyView(generics.DestroyAPIView):
    queryset = Employee.objects.all()
    serializer_class = EmployeeSerializer

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(
            {"message": "Employee deleted successfully"},
            status=status.HTTP_200_OK,
        )

# Table management
class TableListView(generics.ListAPIView):
    serializer_class = TableSerializer

    def get_queryset(self):
        return Table.objects.filter(restaurant_id=self.kwargs["restaurant_pk"])
        
class TableCreateView(generics.CreateAPIView):
    serializer_class = TableManageSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            restaurant = Restaurant.objects.get(pk=self.kwargs["restaurant_pk"])
            serializer.save(restaurant=restaurant)
            return Response(
                {"message": "Table created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {"message": "Failed to create table", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


class TableDetailView(generics.RetrieveAPIView):
    serializer_class = TableSerializer

    def get_queryset(self):
        return Table.objects.filter(restaurant_id=self.kwargs["restaurant_pk"])
        
class TableUpdateView(generics.UpdateAPIView):
    queryset = Table.objects.all()
    serializer_class = TableManageSerializer

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Table updated successfully", "data": serializer.data},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"message": "Failed to update table", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )
        
class TableDestroyView(generics.DestroyAPIView):
    queryset = Table.objects.all()
    serializer_class = TableSerializer

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(
            {"message": "Table deleted successfully"}, status=status.HTTP_200_OK
        )

# Point management
class PointListCreateView(generics.ListCreateAPIView):
    serializer_class = PointSerializer

    def get_queryset(self):
        return Point.objects.filter(restaurant_id=self.kwargs["restaurant_pk"])

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            restaurant = Restaurant.objects.get(pk=self.kwargs["restaurant_pk"])
            serializer.save(restaurant=restaurant)
            return Response(
                {"message": "Point created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {"message": "Failed to create point", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


class PointDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = PointSerializer

    def get_queryset(self):
        return Point.objects.filter(restaurant_id=self.kwargs["restaurant_pk"])

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Point updated successfully", "data": serializer.data},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"message": "Failed to update point", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(
            {"message": "Point deleted successfully"}, status=status.HTTP_200_OK
        )

# Menu Item management

        
class MenuItemListView(generics.ListAPIView):
    serializer_class = MenuItemSerializer

    def get_queryset(self):
        return MenuItem.objects.filter(restaurant_id=self.kwargs["restaurant_pk"])

class MenuItemCreateView(generics.CreateAPIView):
    serializer_class = MenuItemManageSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            restaurant = Restaurant.objects.get(pk=self.kwargs["restaurant_pk"])
            serializer.save(restaurant=restaurant)
            return Response(
                {"message": "Menu item created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {"message": "Failed to create menu item", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )

class MenuItemDetailView(generics.RetrieveAPIView):
    queryset = MenuItem.objects.all()
    serializer_class = MenuItemSerializer

    def get_queryset(self):
        return MenuItem.objects.filter(restaurant_id=self.kwargs["restaurant_pk"])

class MenuItemUpdateView(generics.UpdateAPIView):
    queryset = MenuItem.objects.all()
    serializer_class = MenuItemManageSerializer

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Menu item updated successfully", "data": serializer.data},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"message": "Failed to update menu item", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )
        
class MenuItemDestroyView(generics.DestroyAPIView):
    queryset = MenuItem.objects.all()
    serializer_class = MenuItemSerializer

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(
            {"message": "Menu item deleted successfully"},
            status=status.HTTP_200_OK,
        )

class OrderListView(generics.ListAPIView):
    serializer_class = OrderSerializer

    def get_queryset(self):
        return Order.objects.filter(restaurant_id=self.kwargs["restaurant_pk"])


class OrderCreateView(generics.CreateAPIView):
    serializer_class = OrderManageSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            restaurant = Restaurant.objects.get(pk=self.kwargs["restaurant_pk"])
            serializer.save(restaurant=restaurant)
            return Response(
                {"message": "Order created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {"message": "Failed to create order", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


class OrderDetailView(generics.RetrieveAPIView):
    serializer_class = OrderSerializer

    def get_queryset(self):
        return Order.objects.filter(restaurant_id=self.kwargs["restaurant_pk"])


class OrderUpdateView(generics.UpdateAPIView):
    queryset = Order.objects.all()
    serializer_class = OrderManageSerializer

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)  # Ensure partial updates are handled
        instance = self.get_object()
        previous_status = instance.status
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            updated_order = serializer.save()
            if updated_order.status != previous_status:
                OrderStatusHistory.objects.create(
                    order=updated_order, status=updated_order.status
                )
            return Response(
                {"message": "Order updated successfully", "data": serializer.data},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"message": "Failed to update order", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


class OrderItemListCreateView(generics.ListCreateAPIView):
    serializer_class = OrderItemSerializer

    def get_queryset(self):
        return OrderItem.objects.filter(
            order__restaurant_id=self.kwargs["restaurant_pk"]
        )

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            order = Order.objects.get(pk=self.kwargs["order_pk"])
            serializer.save(order=order)
            return Response(
                {"message": "Order item created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        return Response(
            {"message": "Failed to create order item", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


class OrderItemDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = OrderItemSerializer

    def get_queryset(self):
        return OrderItem.objects.filter(
            order__restaurant_id=self.kwargs["restaurant_pk"]
        )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Order item updated successfully", "data": serializer.data},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"message": "Failed to update order item", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(
            {"message": "Order item deleted successfully"},
            status=status.HTTP_200_OK,
        )


class OrderCancelView(generics.UpdateAPIView):
    queryset = Order.objects.all()
    serializer_class = OrderCancelSerializer

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.status in ["COMPLETED", "CANCELLED"]:
            return Response(
                {"message": "Cannot cancel a completed or already cancelled order."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = self.get_serializer(
            instance, data={"status": "CANCELLED"}, partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Order cancelled successfully", "data": serializer.data},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"message": "Failed to cancel order", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


class OrderItemCancelView(generics.UpdateAPIView):
    queryset = OrderItem.objects.all()
    serializer_class = OrderItemCancelSerializer

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        order = instance.order
        if order.status in ["COMPLETED", "CANCELLED"]:
            return Response(
                {
                    "message": "Cannot cancel an item from a completed or already cancelled order."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = self.get_serializer(instance, data={}, partial=True)
        if serializer.is_valid():
            serializer.save()
            # Check if the entire order was canceled
            if order.status == "CANCELLED":
                return Response(
                    {
                        "message": "Order item canceled successfully. The entire order was canceled as no items remain."
                    },
                    status=status.HTTP_200_OK,
                )
            return Response(
                {"message": "Order item canceled successfully"},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"message": "Failed to cancel order item", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )
