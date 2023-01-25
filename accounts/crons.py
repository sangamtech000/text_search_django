from accounts.models import *
from datetime import datetime
from django.db.models import Q

def clear_prev_data():
    created_date = datetime.now().date()
    created_date = datetime.strptime(str(created_date),"%Y-%m-%d")
    order_delivery_obj=ordersdelivery.objects.filter(~Q(created_date__date=created_date),status='Pending',is_deleted=0)
    order_delivery_obj.update(status='Canceled',reason="driver's irresponsible behaviour")

    vehicle_list=[]
    for data in order_delivery_obj:
        if data.vehicle_id not in vehicle_list:
            vehicle_list.append(data.vehicle_id)
    order_delivery_obj=ordersdelivery.objects.filter(~Q(created_date__date=created_date),is_deleted=0)
    order_delivery_obj.update(is_deleted=1)
    
    vehicle_obj = vehicleinfo.objects.filter(id__in=vehicle_list)
    vehicle_obj.update(is_vehicle_not_available=0)
    print("Cron successfully finished")